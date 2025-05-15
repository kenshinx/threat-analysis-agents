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


def handle_input_and_history(user_input: str, history: List[List[str]]) -> List[List[str]]:
    # handle the user input and history, accroding to OpenAI Message format
    if not user_input.strip():
        return history
    messages = []
    for item in history:
        messages.append({"role": item["role"], "content": item["content"]})
    messages.append({"role": "user", "content": user_input})
    return messages


async def chat_with_agent(user_input, history):
    print(f"User input: {user_input}")
    print(f"Chat history: {history}")
    messages = handle_input_and_history(user_input, history)
    try:
        # Run the triage_agent with the user input
        await ip_mcp_server.connect()
        await basic_mcp_server.connect()
        await domain_mcp_server.connect()
        result = await Runner.run(
            triage_agent,
            messages,
            run_config=RunConfig(model_provider=model_provider,
                                 workflow_name="ctia_threat_analysis_agents")
        )
        return result.final_output
    except Exception as e:
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

if __name__ == "__main__":
    chatbot.launch()
