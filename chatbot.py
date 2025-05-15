import gradio as gr
import asyncio
from typing import List
from agents import Runner, RunConfig
from openai.types.responses import ResponseTextDeltaEvent
from xagents import triage_agent
from manager import VolcanoEngineClient, VolModelProvider
from mcps.mcp_servers import (ip_mcp_server,
                              basic_mcp_server,
                              domain_mcp_server
                              )

# Initialize the model provider
client = VolcanoEngineClient()
model_provider = VolModelProvider(client)

# Initialize MCP servers at startup


async def initialize_mcp_servers():
    await ip_mcp_server.connect()
    await basic_mcp_server.connect()
    await domain_mcp_server.connect()


# Function to handle user input and history for the openai agent need formation


def handle_input_and_history(user_input: str, history: List[List[str]]) -> List[List[str]]:
    if not user_input.strip():
        return history
    messages = []
    for item in history:
        messages.append({"role": item["role"], "content": item["content"]})
    messages.append({"role": "user", "content": user_input})
    return messages

# Function to handle user input and interact with triage_agent in a streaming manner


async def chat_with_agent_stream(user_input, history):
    messages = handle_input_and_history(user_input, history)
    try:
        result_stream = Runner.run_streamed(
            triage_agent,
            messages,
            run_config=RunConfig(model_provider=model_provider,
                                 workflow_name="ctia_threat_analysis_agents")
        )
        full_content = ""
        async for event in result_stream.stream_events():
            if event.type == "raw_response_event" and isinstance(event.data, ResponseTextDeltaEvent):
                full_content += event.data.delta
                yield {"role": "assistant", "content": full_content}
    except Exception as e:
        yield {"role": "assistant", "content": f"Error: {e}"}
        raise e

# Wrapper to handle streaming results for Gradio


async def chat_with_agent_stream_wrapper(user_input, history):
    await initialize_mcp_servers()  # Ensure MCP servers are initialized
    async for message in chat_with_agent_stream(user_input, history):
        yield message

# Gradio ChatInterface with streaming
with gr.Blocks(theme=gr.themes.Monochrome()) as chatbot:
    gr.ChatInterface(
        fn=chat_with_agent_stream_wrapper,  # Use the wrapper to handle streaming
        chatbot=gr.Chatbot(height=700),
        textbox=gr.Textbox(
            placeholder="Analyze Domain/IP/Hash/Vuln/CVE",
            label="User Input",
        ),
        title="Cybersecurity Analyze Agent",
        description="Ask me anything about cybersecurity threats!",
        cache_examples=True,
        type="messages",
    )

chatbot.launch()
