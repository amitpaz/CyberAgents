#!/usr/bin/env python3
"""
Main script to orchestrate the domain intelligence crew's operation, driven by user prompts.
Dynamically loads agents and assigns tasks to a central manager agent.
"""

import asyncio
import logging
import os
import importlib
import inspect
from pathlib import Path
from typing import Dict, List, Optional, Type
import json
import argparse # Import argparse for CLI arguments
import time # Import time for monotonic clock

from crewai import Agent, Crew, Task
from dotenv import load_dotenv
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.instrumentation.logging import LoggingInstrumentor
from opentelemetry.metrics import get_meter_provider, set_meter_provider
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter

# Import Rich for console output
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown

# Dynamically load agent base classes (adjust if base classes are defined elsewhere)
# Assuming agent classes are defined directly in modules like domain_whois_agent.py
# If there's a common base class, import it here.

# Configure logging with OpenTelemetry
LoggingInstrumentor().instrument()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

def setup_telemetry():
    """Configure OpenTelemetry with local and remote exporters."""
    # Create resource
    resource = Resource.create({
        "service.name": "domain-intelligence-crew",
        "service.version": "1.0.0",
    })

    # Configure tracing
    tracer_provider = TracerProvider(resource=resource)
    
    # Add console exporter for local development
    console_exporter = ConsoleSpanExporter()
    tracer_provider.add_span_processor(BatchSpanProcessor(console_exporter))
    
    # Add OTLP trace exporter if configured
    if os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"):
        otlp_trace_exporter = OTLPSpanExporter()
        tracer_provider.add_span_processor(BatchSpanProcessor(otlp_trace_exporter))
    
    trace.set_tracer_provider(tracer_provider)

    # Configure metrics
    metric_readers = []
    # Add OTLP metric exporter if configured
    if os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"):
        otlp_metric_exporter = OTLPMetricExporter()
        metric_reader = PeriodicExportingMetricReader(
            otlp_metric_exporter,
            export_interval_millis=5000
        )
        metric_readers.append(metric_reader)
    
    # If no readers are configured (e.g., no OTLP endpoint), don't set up metrics
    if metric_readers:
        meter_provider = MeterProvider(
            resource=resource,
            metric_readers=metric_readers
        )
        set_meter_provider(meter_provider)
    else:
        # Optionally set a no-op meter provider if no exporters are configured
        set_meter_provider(MeterProvider(resource=resource))
        logger.warning("No OTLP endpoint configured, metrics export is disabled.")

def discover_and_load_agents(base_path: str = "agents") -> Dict[str, Type]:
    """Dynamically discovers and loads agent classes from subdirectories."""
    agent_classes = {}
    agents_dir = Path(base_path)
    
    if not agents_dir.is_dir():
        logger.error(f"Agents directory not found: {base_path}")
        return agent_classes

    for item in agents_dir.iterdir():
        if item.is_dir() and (item / "__init__.py").exists():
            module_name = item.name
            # Try to import the primary module within the subdirectory
            try:
                module_path = f"{base_path}.{module_name}.{module_name}" # e.g., agents.domain_whois_agent.domain_whois_agent
                module = importlib.import_module(module_path)
                
                # Find classes within the module (could add checks for a base class)
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    # Heuristic: Assume class name matches module name pattern or ends with 'Agent'
                    # You might need a more robust way to identify agent classes (e.g., base class check)
                    if name.endswith("Agent") and obj.__module__ == module.__name__:
                        if name in agent_classes:
                             logger.warning(f"Duplicate agent class name found: {name}. Overwriting.")
                        agent_classes[name] = obj
                        logger.info(f"Discovered agent class: {name} from {module_path}")
                        break # Assume one main agent class per module for now
            except ImportError as e:
                logger.error(f"Failed to import module {module_path}: {e}")
            except Exception as e:
                 logger.error(f"Error loading agent from {module_name}: {e}")
                 
    if not agent_classes:
         logger.error(f"No agent classes were discovered in {base_path}. Ensure agent modules and classes are correctly defined.")
         
    return agent_classes

class DomainIntelligenceCrew:
    """Orchestrates the domain intelligence analysis crew, managed by a Security Manager."""

    def __init__(self):
        """Initialize the crew by discovering and instantiating all agents."""
        self.tracer = trace.get_tracer(__name__)
        self.meter = get_meter_provider().get_meter(__name__) # Assuming telemetry setup handles potential errors
        
        # Metrics setup (assuming meter is valid)
        self.analysis_duration = self.meter.create_histogram(
            "analysis.duration", unit="ms", description="Duration of domain analysis"
        )
        self.analysis_errors = self.meter.create_counter(
            "analysis.errors", unit="1", description="Number of analysis errors"
        )
        
        # Discover and load agent classes
        self.agent_classes = discover_and_load_agents()
        if not self.agent_classes:
            raise RuntimeError("Failed to discover any agents. Cannot initialize crew.")
        
        # Instantiate agents
        self.agents_instances = {}
        self.crew_agents = []
        self.manager_agent_instance = None
        
        for name, AgentClass in self.agent_classes.items():
            try:
                instance = AgentClass()
                self.agents_instances[name] = instance
                # Assuming each class instance has an 'agent' attribute holding the crewai.Agent
                if hasattr(instance, 'agent') and isinstance(instance.agent, Agent):
                    self.crew_agents.append(instance.agent)
                    if name == "SecurityManagerAgent": # Identify the manager
                         self.manager_agent_instance = instance
                else:
                     logger.error(f"Agent class {name} does not have a valid 'agent' attribute of type crewai.Agent.")
            except Exception as e:
                logger.error(f"Failed to instantiate agent {name}: {e}")
                # Decide if you want to continue or raise an error

        if not self.crew_agents:
             raise RuntimeError("No valid crewai.Agent instances were created. Cannot initialize crew.")
        if not self.manager_agent_instance:
             raise RuntimeError("SecurityManagerAgent instance not found or failed to load. Cannot initialize crew.")
             
        # Create the Crew with all discovered agents
        self.crew = Crew(
            agents=self.crew_agents,
            tasks=[],
            verbose=True,
            memory=True,
            # manager_llm=self.manager_agent_instance.agent.llm # Example: Ensure manager uses its own LLM if needed
        )

    def run_analysis(self, user_prompt: str) -> Dict:
        """Runs analysis based on user prompt, orchestrated by the Security Manager."""
        with self.tracer.start_as_current_span("run_analysis") as span:
            span.set_attribute("user_prompt", user_prompt)
            logger.info(f"Received analysis request: \"{user_prompt}\"")
            start_time = time.monotonic()
            
            # Build dynamic description of available agents for the manager
            available_specialists_desc = "\nAvailable Specialist Agents:\n"
            for name, instance in self.agents_instances.items():
                 if name != "SecurityManagerAgent": # Exclude manager itself
                      agent = instance.agent
                      available_specialists_desc += f"- {agent.role}: Goal - {agent.goal}\n"
                      if agent.tools:
                           tool_names = ", ".join([tool.name for tool in agent.tools])
                           available_specialists_desc += f"    Tools: [{tool_names}]\n"
            
            manager_task_description = (
                f"Process the user request: '{user_prompt}'. "
                f"Identify the target entities (like domains) and required analysis types. "
                f"{available_specialists_desc}"
                f"Delegate specific analysis sub-tasks to the appropriate specialist agents based on their roles and tools. "
                f"Ensure you provide the necessary inputs for each delegated task (e.g., domain name). "
                f"If one task's output is needed for another (e.g., WHOIS data for Threat Intel), manage the data flow. "
                f"Synthesize the structured results from all delegated analyses into a comprehensive final report."
            )

            manager_expected_output = (
                "A comprehensive, well-structured security report addressing the user's request, "
                "integrating findings from all delegated analyses (e.g., WHOIS, DNS, Threat Intelligence). "
                "The report should clearly present the gathered data in an organized manner."
            )

            try:
                manager_task = Task(
                    description=manager_task_description,
                    agent=self.manager_agent_instance.agent,
                    expected_output=manager_expected_output
                )
                
                self.crew.tasks = [manager_task]
                final_result = self.crew.kickoff()
                duration = (time.monotonic() - start_time) * 1000
                
                # Record metrics (assuming they were created successfully)
                try:
                    if self.analysis_duration: self.analysis_duration.record(duration)
                except Exception as metric_err:
                     logger.warning(f"Failed to record duration metric: {metric_err}")
                
                # The final result should be the compiled report from the manager
                # It might be a string (Markdown?) or a complex dict. We'll handle string for now.
                return {"analysis_report": str(final_result)}
                
            except Exception as e:
                 try:
                     if self.analysis_errors: self.analysis_errors.add(1)
                 except Exception as metric_err:
                      logger.warning(f"Failed to record error metric: {metric_err}")
                      
                 error_message = f"Error running analysis for prompt \"{user_prompt}\": {str(e)}"
                 logger.error(error_message, exc_info=True) # Log traceback
                 span.record_exception(e)
                 return {"error": error_message, "exception": str(e)}

def display_results(results: Dict):
    """Displays the analysis results using Rich."""
    console = Console()
    console.print("\n" + "-"*50) 

    if "error" in results:
        console.print(Panel(
            f"[bold red]Error during analysis:[/bold red]\n\n{results.get('error', 'Unknown error')}\n\nException: {results.get('exception', 'N/A')}",
            title="Analysis Failed",
            border_style="red"
        ))
    elif "analysis_report" in results:
        report_content = results["analysis_report"]
        # Attempt to render as Markdown, fallback to plain text
        try:
            # Assuming the report is Markdown formatted
            markdown = Markdown(report_content)
            console.print(Panel(
                markdown,
                title="[bold green]Analysis Report[/bold green]",
                border_style="green",
                expand=False # Prevent panel from taking full width if content is short
            ))
        except Exception:
             # Fallback if rendering Markdown fails or content isn't MD
             console.print(Panel(
                report_content,
                title="[bold green]Analysis Report[/bold green]",
                border_style="green",
                expand=False
            ))
    else:
         console.print(Panel(
            "Analysis completed, but no report data found.",
            title="[yellow]Analysis Result[/yellow]",
            border_style="yellow"
         ))
    console.print("-"*50 + "\n")

def main():
    """Main entry point, parses args and runs the analysis."""
    setup_telemetry()
    parser = argparse.ArgumentParser(description="Run security analysis using a managed crew of agents.")
    parser.add_argument("prompt", type=str, help="The user request (e.g., 'Analyze domain walla.co.il')")
    args = parser.parse_args()
    
    try:
        logger.info("Initializing Domain Intelligence Crew...")
        crew_runner = DomainIntelligenceCrew()
        logger.info(f"Starting analysis for prompt: \"{args.prompt}\"")
        results = crew_runner.run_analysis(args.prompt)
        
        # Display results using Rich instead of logging JSON
        display_results(results)
        
    except Exception as e:
        # Use Rich Console for critical errors too
        console = Console()
        console.print(Panel(
            f"[bold red]Critical error during execution:[/bold red]\n\n{str(e)}",
            title="Execution Failed",
            border_style="red"
        ))
        logger.error(f"Critical error during crew initialization or execution: {str(e)}", exc_info=True)

if __name__ == "__main__":
    # Need Console here if main fails before display_results
    from rich.console import Console 
    from rich.panel import Panel
    main() 