import os
import base64
import argparse
import asyncio
import nest_asyncio
import logfire
from openai import AsyncOpenAI
from agents import (Model,
                    Runner,
                    ModelProvider,
                    RunConfig,
                    OpenAIChatCompletionsModel)
from dotenv import load_dotenv

from xagents import triage_agent
from mcps.mcp_servers import (ip_mcp_server,
                              basic_mcp_server,
                              domain_mcp_server
                              )

load_dotenv()
nest_asyncio.apply()

API_KEY = os.getenv("ARK_API_KEY")
BASE_URL = os.getenv("ARK_BASE_URL")
MODEL = os.getenv("ARK_MODEL")


def setup_langfuse():
    LANGFUSE_AUTH = base64.b64encode(
        f"{os.environ.get('LANGFUSE_PUBLIC_KEY')}:{os.environ.get('LANGFUSE_SECRET_KEY')}".encode()
    ).decode()

    os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"] = os.environ.get(
        "LANGFUSE_HOST") + "/api/public/otel"
    os.environ["OTEL_EXPORTER_OTLP_HEADERS"] = f"Authorization=Basic {LANGFUSE_AUTH}"

    logfire.configure(
        service_name='ctia_threat_analysis_agents',
        send_to_logfire=False
    )
    # This method automatically patches the OpenAI Agents SDK to send logs via OTLP to Langfuse.
    logfire.instrument_openai_agents()


class VolcanoEngineClient(AsyncOpenAI):
    def __init__(self):
        super().__init__(
            api_key=API_KEY,
            base_url=BASE_URL,
        )


class VolModelProvider(ModelProvider):

    def __init__(self, client: AsyncOpenAI):
        self.client = client

    def get_model(self, model_name: str | None) -> Model:
        return OpenAIChatCompletionsModel(model=model_name or MODEL, openai_client=self.client)


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "query", help="Cybersecuirty threat analyze，such as analyze: example.com")
    args = parser.parse_args()

    setup_langfuse()

    client = VolcanoEngineClient()
    model_provider = VolModelProvider(client)

    try:
        await ip_mcp_server.connect()
        await basic_mcp_server.connect()
        await domain_mcp_server.connect()

        result = await Runner.run(triage_agent, args.query, run_config=RunConfig(model_provider=model_provider, workflow_name="ctia_threat_analysis_agents"))

        return result.final_output

    except Exception as e:
        print(f"Error occurred: {e}")
        raise

    finally:
        await ip_mcp_server.cleanup()
        await basic_mcp_server.cleanup()
        await domain_mcp_server.cleanup()

if __name__ == "__main__":
    try:
        result = asyncio.run(main())
        print(result)
    except Exception as e:
        print(f"Unhandled exception: {e}")
