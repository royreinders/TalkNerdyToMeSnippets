#!/usr/bin/env python3
"""
OC2 Ollama Client that interacts with FastMCP tool
"""
import asyncio
import ollama
import json
from fastmcp import Client

class OC2OllamaClient:
    def __init__(self, mcp_server_url: str = "IP ADDRESS", ollama_model: str = "llama3.1"):
        self.mcp_server_url = mcp_server_url
        self.mcp_client = Client(mcp_server_url)
        self.ollama_model = ollama_model

    async def get_active_implants(self):
        """Get active implants from MCP tool"""
        try:
            async with self.mcp_client:
                result = await self.mcp_client.call_tool("list")

               
                tool_result = result

                if hasattr(tool_result, "structured_content") and isinstance(tool_result.structured_content, dict):
                    return tool_result.structured_content.get("result", [])

                elif hasattr(tool_result, 'text'):
                    try:
                        return json.loads(tool_result.text)
                    except json.JSONDecodeError as e:
                        print(f"Failed to parse .text as JSON: {e}")
                        print(f"Raw text: {tool_result.text}")
                        return []

                else:
                    print(f"No usable content found in tool result: {tool_result}")
                    return []

        except Exception as e:
            print(f"Error fetching implants: {e}")
            return []


    def format_implant_info(self, implants):
        """Format implant information for context"""
        if not implants:
            return "No active implants found."

        context = f"Active implants: {len(implants)} systems\n\n"

        for implant in implants:
            if isinstance(implant, dict):
                uid = implant.get('implant_uid', 'Unknown')
                hostname = implant.get('hostname', 'Unknown')
                username = implant.get('username', 'Unknown')
                os_info = implant.get('os', 'unknown')
                arch = implant.get('arch', 'unknown')
                pid = implant.get('pid', 0)
                proc_name = implant.get('proc_name', 'unknown')
                first_seen = implant.get('first_seen', 'Never')
                last_checkin = implant.get('last_checkin', 'Never')

                context += f"Implant ID: {uid}\n"
                context += f"  Host: {hostname}\n"
                context += f"  User: {username}\n"
                context += f"  OS: {os_info}\n"
                context += f"  Architecture: {arch}\n"
                context += f"  Process: {proc_name} (PID: {pid})\n"
                context += f"  First Seen: {first_seen}\n"
                context += f"  Last Check-in: {last_checkin}\n\n"

        return context

    async def chat_with_context(self, user_message: str):
        """Send message to Ollama with implant context"""
        implants = await self.get_active_implants()
        context = self.format_implant_info(implants)

        system_prompt = f"""You are an AI assistant helping manage an OC2 Command & Control infrastructure.

Current Status:
{context}

You can help with:
- Analyzing implant status and health
- Identifying potential issues or anomalies
- Suggesting operational actions
- Explaining implant data and metrics
- General C2 operational guidance

Always be concise and security-minded in your responses."""

        messages = [
            {'role': 'system', 'content': system_prompt},
            {'role': 'user', 'content': user_message}
        ]

        try:
            response = ollama.chat(model=self.ollama_model, messages=messages)
            return response['message']['content']
        except Exception as e:
            return f"Ollama Error: {e}"

async def main():
    print("OC2 Ollama Client Starting...")
    client = OC2OllamaClient()

    # Fetch and display implants
    print("\n" + "="*50)
    print("FETCHING ACTIVE IMPLANTS")
    print("="*50)

    implants = await client.get_active_implants()

    if implants:
        print(f"Found {len(implants)} active implants:\n")

        for i, implant in enumerate(implants, 1):
            if isinstance(implant, dict):
                uid = implant.get('implant_uid', 'Unknown')
                hostname = implant.get('hostname', 'Unknown')
                username = implant.get('username', 'Unknown')
                last_checkin = implant.get('last_checkin', 'Never')
                print(f"{i}. [{uid}] {hostname} ({username}) - Last seen: {last_checkin}")
    else:
        print("No implants found or error occurred.")

    # Interactive chat
    print("\n" + "="*50)
    print("INTERACTIVE CHAT MODE")
    print("="*50)
    print("Ask questions about your implants or C2 operations.")
    print("Type 'refresh' to reload implant data, 'quit' to exit.\n")

    while True:
        try:
            user_input = input("RedAI> ").strip()

            if user_input.lower() in ['quit', 'exit', 'q']:
                print("Goodbye!")
                break
            elif user_input.lower() == 'refresh':
                implants = await client.get_active_implants()
                print(f"Refreshed: Found {len(implants)} active implants")
                continue
            elif not user_input:
                continue

            print("Thinking...")
            response = await client.chat_with_context(user_input)
            print(f"\nRedAI: {response}\n")

        except KeyboardInterrupt:
            print("\nGoodbye!")
            break
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(main())
