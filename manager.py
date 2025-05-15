import os
import base64
import nest_asyncio
import logfire
from openai import AsyncOpenAI
from agents import (Model,
                    ModelProvider,
                    OpenAIChatCompletionsModel)
from dotenv import load_dotenv


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


setup_langfuse()


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
