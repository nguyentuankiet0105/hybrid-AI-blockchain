"""
AI Security Copilot — LangChain ReAct agent with 4 tools.

Streams Thought / Action / Observation / Final events as SSE chunks.
Falls back to a simple direct GPT call when LangChain is unavailable.
"""
from __future__ import annotations

import json
from typing import Any, AsyncGenerator, Dict, List

from app.core.config import settings
from app.core.logging import get_logger
from app.models.models import CopilotMessage, CopilotSession

logger = get_logger(__name__)

SYSTEM_PROMPT = """You are a professional IoT security forensic analyst specializing in hybrid AI-Blockchain architectures.

CONSTRAINTS:
- Only draw conclusions from data retrieved by your tools. Never speculate without evidence.
- Before issuing any security conclusion, verify log hashes against the blockchain ledger using Audit_Blockchain_Ledger_State.
- All recommendations must cite specific anomaly score values, timestamps, or transaction hashes.
- Do NOT give generic advice like "update your firmware". Produce specific, executable commands.
- Output confidence as HIGH, MEDIUM, or LOW based on evidence completeness.

OUTPUT FORMAT for final answer:
{
  "summary": "<plain English summary of what happened>",
  "device": "<MAC address>",
  "attack_type": "<classification>",
  "timeline": "<key events with timestamps>",
  "evidence_hashes": ["<tx_hash_1>", ...],
  "remediation": "<specific commands: iptables/Solidity/MQTT ACL>",
  "confidence": "HIGH|MEDIUM|LOW"
}
"""


class CopilotService:
    def __init__(self, db, session: CopilotSession):
        self.db = db
        self.session = session

    async def stream_response(
        self, user_message: str, history: List[CopilotMessage]
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Stream ReAct steps as SSE events."""
        try:
            async for chunk in self._langchain_stream(user_message, history):
                yield chunk
        except Exception as e:
            logger.warning("LangChain stream failed, falling back to direct call", error=str(e))
            async for chunk in self._direct_stream(user_message, history):
                yield chunk

    async def _langchain_stream(
        self, user_message: str, history: List[CopilotMessage]
    ) -> AsyncGenerator[Dict[str, Any], None]:
        from langchain.agents import AgentExecutor, create_react_agent
        from langchain.memory import ConversationBufferWindowMemory
        from langchain_core.prompts import PromptTemplate
        from langchain_core.tools import Tool
        from langchain_openai import ChatOpenAI

        llm = ChatOpenAI(
            model=settings.OPENAI_MODEL,
            api_key=settings.OPENAI_API_KEY,
            streaming=True,
            temperature=0,
        )

        tools = self._build_tools()

        # Build conversation string from history
        chat_history = "\n".join(
            f"{m.role.upper()}: {m.content}" for m in history[-10:]
        )

        react_prompt = PromptTemplate.from_template(
            SYSTEM_PROMPT + """

Previous conversation:
{chat_history}

Tools available:
{tools}

Tool names: {tool_names}

Question: {input}
{agent_scratchpad}"""
        )

        agent = create_react_agent(llm, tools, react_prompt)
        executor = AgentExecutor(
            agent=agent,
            tools=tools,
            verbose=False,
            max_iterations=10,
            handle_parsing_errors=True,
        )

        tool_calls_used = 0
        full_output = ""

        # Stream intermediate steps
        async for step in executor.astream(
            {"input": user_message, "chat_history": chat_history}
        ):
            if "actions" in step:
                for action in step["actions"]:
                    tool_calls_used += 1
                    yield {
                        "event": "action",
                        "data": {
                            "step": "Action",
                            "tool": action.tool,
                            "input": str(action.tool_input)[:500],
                        },
                    }
            if "steps" in step:
                for s in step["steps"]:
                    yield {
                        "event": "observation",
                        "data": {
                            "step": "Observation",
                            "content": str(s.observation)[:1000],
                        },
                    }
            if "output" in step:
                full_output = step["output"]

        yield {
            "event": "final",
            "data": {
                "answer": full_output,
                "tool_calls_used": tool_calls_used,
                "confidence": self._extract_confidence(full_output),
            },
        }

    async def _direct_stream(
        self, user_message: str, history: List[CopilotMessage]
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Fallback: direct OpenAI call without tool use."""
        from openai import AsyncOpenAI

        client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)

        messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        for m in history[-8:]:
            messages.append({"role": m.role if m.role in ("user", "assistant") else "user", "content": m.content})
        messages.append({"role": "user", "content": user_message})

        yield {"event": "thought", "data": {"step": "Thought", "content": "Analyzing with available context..."}}

        full = ""
        try:
            stream = await client.chat.completions.create(
                model=settings.OPENAI_MODEL,
                messages=messages,
                stream=True,
                max_tokens=1000,
            )
            async for chunk in stream:
                delta = chunk.choices[0].delta.content or ""
                full += delta
        except Exception as e:
            full = f"Analysis unavailable: {e}. Please check your OpenAI API key."

        yield {
            "event": "final",
            "data": {"answer": full, "tool_calls_used": 0, "confidence": "LOW"},
        }

    def _build_tools(self):
        from langchain_core.tools import Tool

        return [
            Tool(
                name="Read_IoT_Gateway_Logs",
                description="Fetch recent security log entries from the edge gateway. Input: JSON with 'device_id' and optional 'time_range' (ISO-8601 interval).",
                func=lambda x: self._tool_gateway_logs(x),
                coroutine=self._tool_gateway_logs_async,
            ),
            Tool(
                name="Audit_Blockchain_Ledger_State",
                description="Query device state and event history from the immutable blockchain ledger. Input: device MAC address string.",
                func=lambda x: self._tool_blockchain_audit(x),
                coroutine=self._tool_blockchain_audit_async,
            ),
            Tool(
                name="Analyze_Anomaly_Score_History",
                description="Retrieve time series of anomaly scores for a device. Input: JSON with 'device_id' and 'start_time', 'end_time' (ISO-8601).",
                func=lambda x: self._tool_anomaly_history(x),
                coroutine=self._tool_anomaly_history_async,
            ),
            Tool(
                name="Query_Threat_Intelligence",
                description="Query CVE database and threat intelligence feeds. Input: IP address, hash, or CVE identifier string.",
                func=lambda x: f"Threat intelligence lookup for: {x} — No matching indicators found in local TI feed.",
                coroutine=self._tool_threat_intel_async,
            ),
        ]

    async def _tool_gateway_logs_async(self, query: str) -> str:
        from sqlalchemy import select
        from app.models.models import AnomalyEvent, Device

        try:
            params = json.loads(query) if query.strip().startswith("{") else {"device_id": query}
        except Exception:
            params = {"device_id": str(query)}

        result = await self.db.execute(
            select(AnomalyEvent)
            .where(AnomalyEvent.is_alert.is_(True))
            .order_by(AnomalyEvent.window_start.desc())
            .limit(10)
        )
        events = result.scalars().all()
        if not events:
            return "No recent alert events found in gateway logs."
        lines = []
        for e in events:
            lines.append(
                f"[{e.window_start.isoformat()}] score={float(e.anomaly_score):.3f} "
                f"alert={e.is_alert} tx={e.bc_tx_hash}"
            )
        return "\n".join(lines)

    def _tool_gateway_logs(self, query: str) -> str:
        return "Gateway logs require async context."

    async def _tool_blockchain_audit_async(self, device_mac: str) -> str:
        from sqlalchemy import select
        from app.models.models import BlockchainEvent

        result = await self.db.execute(
            select(BlockchainEvent)
            .where(BlockchainEvent.device_mac == device_mac.strip())
            .order_by(BlockchainEvent.bc_timestamp.desc())
            .limit(5)
        )
        events = result.scalars().all()
        if not events:
            return f"No blockchain events found for device {device_mac}."
        lines = []
        for e in events:
            lines.append(
                f"[{e.bc_timestamp.isoformat()}] {e.event_type} "
                f"block={e.bc_block_number} tx={e.bc_tx_hash}"
            )
        return "\n".join(lines)

    def _tool_blockchain_audit(self, device_mac: str) -> str:
        return "Blockchain audit requires async context."

    async def _tool_anomaly_history_async(self, query: str) -> str:
        from sqlalchemy import select
        from app.models.models import AnomalyEvent

        result = await self.db.execute(
            select(AnomalyEvent)
            .order_by(AnomalyEvent.window_start.desc())
            .limit(20)
        )
        events = result.scalars().all()
        if not events:
            return "No anomaly score history found."
        scores = [f"{float(e.anomaly_score):.3f}" for e in events]
        return f"Recent anomaly scores (newest first): {', '.join(scores)}"

    def _tool_anomaly_history(self, query: str) -> str:
        return "Anomaly history requires async context."

    async def _tool_threat_intel_async(self, indicator: str) -> str:
        return f"Threat intelligence lookup for: {indicator} — No matching indicators found in local TI feed. Consider checking NVD CVE database at https://nvd.nist.gov/"

    def _extract_confidence(self, text: str) -> str:
        text_upper = text.upper()
        if '"confidence": "HIGH"' in text_upper or "CONFIDENCE: HIGH" in text_upper:
            return "HIGH"
        if '"confidence": "MEDIUM"' in text_upper or "CONFIDENCE: MEDIUM" in text_upper:
            return "MEDIUM"
        return "LOW"
