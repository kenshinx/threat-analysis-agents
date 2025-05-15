import gradio as gr
import asyncio
from typing import List
from agents import Runner, RunConfig
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

# Function to handle user input and interact with triage_agent


async def chat_with_agent(user_input, history):
    messages = handle_input_and_history(user_input, history)
    try:
        await ip_mcp_server.connect()
        await basic_mcp_server.connect()
        await domain_mcp_server.connect()
        # Run the triage_agent with the user input
        result = await Runner.run(
            triage_agent,
            messages,
            run_config=RunConfig(model_provider=model_provider,
                                 workflow_name="ctia_threat_analysis_agents")
        )
        return result.final_output
    except Exception as e:
        raise e
        return str(e)

# Gradio ChatInterface
with gr.Blocks() as chatbot:
    gr.ChatInterface(
        fn=lambda user_input, history: asyncio.run(
            chat_with_agent(user_input, history)),
        chatbot=gr.Chatbot(height=500),
        textbox=gr.Textbox(
            placeholder="Analyze Domain/IP/Hash/Vuln/CVE",
            label="User Input",),
        title="Cybersecurity Analyze Agent",
        description="Ask me anything about cybersecurity threats!",
        cache_examples=True,
        type="messages"
    )


async def main():
    # Initialize MCP servers at startup
    await initialize_mcp_servers()

    # Launch the Gradio app
    chatbot.launch()

if __name__ == "__main__":
    asyncio.run(main())
