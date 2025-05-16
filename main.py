import argparse
import asyncio
from agents import (Runner,
                    RunConfig
                    )

from xagents import triage_agent
from mcps.mcp_servers import (ip_mcp_server,
                              basic_mcp_server,
                              domain_mcp_server
                              )
from manager import VolcanoEngineClient, VolModelProvider


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "query", help="Cybersecuirty threat analyze，such as analyze: example.com")
    args = parser.parse_args()

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
