#!/usr/bin/env python3
"""
robot_simulator.py — AAMS 장비 제어 모의 스크립트 (브리지 호환)

* fingerprint_bridge.js 에서 mission_controller_with_vision.py 대신 사용할 수 있는
  경량 시뮬레이터.
* TAB ↔ Render 브릿지 최신 인터페이스(bridge-mode, await_user, interaction 등)를
  모방하여 하드웨어 없이 흐름을 점검할 때 사용한다.
* stdin 으로 들어오는 JSON 명령(사용자 인터랙션, lockdown 해제 등)을 수신하며,
  기존 버전에서 사용하던 payload 기반 시뮬레이션 옵션도 유지한다.
"""

from __future__ import annotations

import argparse
import json
import queue
import random
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional

STAGES_RETURN = [
    ("prepare", "반납 준비 중"),
    ("verify", "반납 물품 시각 검사"),
    ("stow", "보관 구역으로 이동"),
    ("complete", "보관 완료"),
]

STAGES_DISPATCH = [
    ("prepare", "불출 준비 중"),
    ("pick", "요청 장비 수거"),
    ("verify", "출고 전 시각 검사"),
    ("handover", "사용자에게 전달"),
]

VISION_CHECKS = [
    ("magazine_top", "탄창 최상단 탄알 위치 확인"),
    ("selector", "조정간 위치 확인"),
    ("serial", "총기 QR 코드 확인"),
]

CANCEL_COMMANDS = {"cancel", "abort", "stop", "fail"}
ACK_COMMANDS = {"resume", "confirm", "proceed", "ok", "continue"}

class SimulationAbort(RuntimeError):
    """사용자 또는 외부 명령으로 취소된 경우"""


def parse_jsonish(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            data = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}
    return {}


def as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def coerce_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        text = value.strip().lower()
        if not text:
            return None
        if text in {"true", "1", "yes", "y", "on"}:
            return True
        if text in {"false", "0", "no", "n", "off"}:
            return False
    return None


def coerce_float(value: Any, default: float) -> float:
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return default
        try:
            return float(text)
        except ValueError:
            try:
                normalized = text.replace(",", ".")
                return float(normalized)
            except ValueError:
                return default
    return default


def pick_bool(*values: Any, default: Optional[bool] = False) -> Optional[bool]:
    for value in values:
        if value is None:
            continue
        if isinstance(value, bool):
            return value
        parsed = coerce_bool(value)
        if parsed is not None:
            return parsed
    return default

class CommandStream:
    """stdin 으로 전달되는 JSON 명령을 읽어오는 헬퍼"""

    def __init__(self) -> None:
        self._queue: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self._initial: Optional[Dict[str, Any]] = None
        self._initial_event = threading.Event()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def _loop(self) -> None:
        while self._running:
            try:
                line = sys.stdin.readline()
            except Exception:
                break
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if (
                self._initial is None
                and not any(key in data for key in ("event", "command", "type"))
            ):
                self._initial = data
                self._initial_event.set()
                continue
            self._queue.put(data)
        self._initial_event.set()
        self._running = False

    def initial_payload(self, timeout: float = 0.15) -> Optional[Dict[str, Any]]:
        self._initial_event.wait(timeout)
        return self._initial

    def get(self, timeout: Optional[float] = 0.0) -> Optional[Dict[str, Any]]:
        block = timeout is None or timeout > 0
        real_timeout = None if timeout is None or timeout <= 0 else timeout
        try:
            return self._queue.get(block=block, timeout=real_timeout)
        except queue.Empty:
            return None

    def drain(self) -> Iterable[Dict[str, Any]]:
        while True:
            try:
                yield self._queue.get_nowait()
            except queue.Empty:
                return


@dataclass
class SimulatorOptions:
    request_id: Optional[str]
    mission_label: Optional[str]
    mission_number: int
    direction: str
    includes_ammo: bool
    site: Optional[str]
    simulate_cfg: Dict[str, Any]
    await_user: bool
    await_stage: Optional[str]
    await_timeout: float
    await_message: str

    @property
    def mode(self) -> str:
        return "dispatch" if self.direction == "out" else "return"


class EventEmitter:
    def __init__(self, options: SimulatorOptions) -> None:
        self.options = options

    def _base_payload(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"mode": self.options.mode}
        if self.options.request_id:
            payload["requestId"] = self.options.request_id
        meta: Dict[str, Any] = {}
        if self.options.mission_label:
            meta.setdefault("missionLabel", self.options.mission_label)
        if self.options.site:
            meta.setdefault("site", self.options.site)
        if self.options.includes_ammo:
            meta.setdefault("includesAmmo", True)
        if meta:
            payload["meta"] = meta
        return payload

    def emit(self, payload: Dict[str, Any]) -> None:
        data = self._base_payload()
        meta = data.get("meta", {}).copy()
        extra_meta = payload.get("meta") if isinstance(payload.get("meta"), dict) else {}
        meta.update(extra_meta)
        merged = {**payload, **data}
        if meta:
            merged["meta"] = meta
        print(json.dumps(merged, ensure_ascii=False), flush=True)

    def progress(self, stage: str, message: str, **extra: Any) -> None:
        payload = {"event": "progress", "stage": stage, "message": message, **extra}
        self.emit(payload)

    def log(self, message: str, *, stage: Optional[str] = None, level: str = "info", **extra: Any) -> None:
        payload = {
            "event": "log",
            "stage": stage,
            "message": message,
            "level": level,
            **extra,
        }
        self.emit(payload)

    def await_user(self, stage: str, message: str) -> str:
        token = f"{stage}-{int(time.time() * 1000)}-{random.randint(1000, 9999)}"
        payload = {"event": "await_user", "stage": stage, "message": message, "token": token}
        self.emit(payload)
        return token

    def await_user_done(self, stage: str, message: str, token: str, **extra: Any) -> None:
        payload = {
            "event": "await_user_done",
            "stage": stage,
            "message": message,
            "token": token,
            **extra,
        }
        self.emit(payload)

    def complete(self, status: str, stage: str, message: str, **extra: Any) -> None:
        payload = {
            "event": "complete",
            "status": status,
            "stage": stage,
            "message": message,
            **extra,
        }
        if status != "success" and "error" not in payload:
            payload["error"] = message
        summary = {
            "requestId": self.options.request_id,
            "mission": self.options.mission_number,
            "mode": self.options.mode,
            "includes": {"ammo": self.options.includes_ammo},
        }
        payload.setdefault("summary", summary)
        self.emit(payload)

def _coerce_int(value: Any, default: int) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return default
        try:
            if "." in text:
                return int(float(text))
            return int(text)
        except ValueError:
            return default
    return default


def simulate_delay(stage: str, simulate_cfg: Dict[str, Any]) -> None:
    delay_cfg = simulate_cfg.get("delay") if isinstance(simulate_cfg, dict) else None
    min_ms = 350
    max_ms = 900
    if isinstance(delay_cfg, dict):
        stage_cfg = delay_cfg.get(stage)
        min_ms = _coerce_int(delay_cfg.get("min"), min_ms)
        max_ms = _coerce_int(delay_cfg.get("max"), max_ms)
        if isinstance(stage_cfg, dict):
            min_ms = _coerce_int(stage_cfg.get("min"), min_ms)
            max_ms = _coerce_int(stage_cfg.get("max"), max_ms)
        elif stage_cfg is not None:
            min_ms = max_ms = _coerce_int(stage_cfg, max_ms)
    elif delay_cfg is not None:
        min_ms = max_ms = _coerce_int(delay_cfg, min_ms)

    min_ms = max(0, min_ms)
    max_ms = max(min_ms, max_ms)
    time.sleep(random.uniform(min_ms, max_ms) / 1000.0)

def resolve_direction(raw: Optional[str]) -> str:
    text = (raw or "").strip().lower()
    if text in {"return", "incoming", "in", "입고", "불입"}:
        return "in"
    return "out" if text in {"dispatch", "issue", "out", "불출"} else "out"


def resolve_mission_number(raw: Optional[Any], fallback: int = 1) -> int:
    if raw is None:
        return fallback
    if isinstance(raw, int):
        return max(1, min(2, raw))
    if isinstance(raw, float):
        return max(1, min(2, int(raw)))
    try:
        text = str(raw)
    except Exception:
        return fallback
    digits = "".join(ch for ch in text if ch.isdigit())
    if digits:
        value = int(digits)
        if value <= 0:
            return fallback
        if value in {1, 2}:
            return value
        return ((value - 1) % 2) + 1
    if "2" in text:
        return 2
    return fallback


def merge_simulate_config(*configs: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    for cfg in configs:
        data = parse_jsonish(cfg)
        if data:
            merged.update(data)
    return merged


def check_for_failure(stage: str, simulate_cfg: Dict[str, Any]) -> None:
    fail_stage = str(simulate_cfg.get("fail_stage") or "").strip().lower()
    if fail_stage and fail_stage == stage.lower():
        reason = simulate_cfg.get("reason") or f"{stage} 단계 실패"
        raise RuntimeError(reason)


def handle_command(
    command: Dict[str, Any],
    *,
    emitter: EventEmitter,
    current_stage: str,
    pending_token: Optional[str],
) -> Optional[str]:
    if not command:
        return None
    if command.get("event") == "lockdown_cleared":
        emitter.log("lockdown 해제 신호 수신", stage=current_stage, level="info", meta=command)
        return None
    action = str(command.get("command") or command.get("action") or "").lower()
    if action in CANCEL_COMMANDS:
        raise SimulationAbort(command.get("message") or "사용자 취소")
    if pending_token and action in ACK_COMMANDS:
        token = command.get("token")
        stage = command.get("stage") or current_stage
        if token and token == pending_token:
            emitter.log(
                f"토큰 {token} 확인 — {action}",
                stage=stage,
                level="info",
                meta={"token": token, "command": action},
            )
            return action
    emitter.log(
        "알 수 없는 명령 수신", stage=current_stage, level="debug", meta=command
    )
    return None


def wait_for_ack(
    listener: CommandStream,
    emitter: EventEmitter,
    stage: str,
    token: str,
    timeout: float,
) -> None:
    deadline = time.time() + max(timeout, 0.1)
    while time.time() < deadline:
        remaining = deadline - time.time()
        command = listener.get(timeout=min(remaining, 0.5))
        if not command:
            continue
        handled = handle_command(command, emitter=emitter, current_stage=stage, pending_token=token)
        if handled:
            return
    emitter.log("사용자 응답 없음 — 자동 진행", stage=stage, level="warning", meta={"token": token})


def run_vision_checks(emitter: EventEmitter, simulate_cfg: Dict[str, Any]) -> None:
    checks = simulate_cfg.get("vision_checks") if isinstance(simulate_cfg, dict) else None
    active_checks = VISION_CHECKS
    if isinstance(checks, list) and checks:
        lookup = {key: label for key, label in VISION_CHECKS}
        active_checks = [(key, lookup.get(key, key)) for key in checks]
    for key, label in active_checks:
        emitter.progress(key, label)
        simulate_delay(key, simulate_cfg)
        check_for_failure(key, simulate_cfg)


def build_simulator_options(args: argparse.Namespace, payload: Optional[Dict[str, Any]]) -> SimulatorOptions:
    payload = payload if isinstance(payload, dict) else {}
    bridge_payload = as_dict(payload.get("bridgePayload"))

    request_id = (
        args.request_id
        or payload.get("requestId")
        or payload.get("request_id")
        or bridge_payload.get("requestId")
        or bridge_payload.get("request_id")
    )
    mission_label = (
        args.mission_label
        or payload.get("missionLabel")
        or payload.get("mission_label")
        or bridge_payload.get("missionLabel")
        or bridge_payload.get("mission_label")
        or payload.get("locker")
    )
    direction = resolve_direction(
        args.direction
        or payload.get("direction")
        or payload.get("mode")
        or bridge_payload.get("direction")
        or bridge_payload.get("mode")
        or payload.get("type")
    )
    mission_number = resolve_mission_number(
        args.mission
        or payload.get("mission")
        or payload.get("missionNumber")
        or bridge_payload.get("mission")
        or mission_label
        or 1
    )

    includes_dict = as_dict(payload.get("includes"))
    bridge_includes = as_dict(bridge_payload.get("includes"))
    includes_ammo = True if args.with_mag else bool(
        pick_bool(
            payload.get("includesAmmo"),
            bridge_payload.get("includesAmmo"),
            includes_dict.get("ammo"),
            bridge_includes.get("ammo"),
        )
    )

    site = (
        args.site
        or payload.get("site")
        or payload.get("site_id")
        or bridge_payload.get("site")
        or bridge_payload.get("site_id")
    )

    simulate_cfg = merge_simulate_config(payload.get("simulate"), args.simulate)

    await_cfg = as_dict(payload.get("await"))
    await_stage = args.await_stage or await_cfg.get("stage")
    await_enabled = args.await_user or pick_bool(await_cfg.get("enabled"))
    await_timeout_raw = args.await_timeout if args.await_timeout is not None else await_cfg.get("timeout", 6.0)
    await_message = args.await_message or await_cfg.get("message") or "사용자 확인 대기"

    if not await_enabled and args.await_user_auto:
        await_enabled = True
        if not await_stage:
            await_stage = "handover" if direction == "out" else "stow"

    if await_enabled and not await_stage:
        await_stage = "handover" if direction == "out" else "stow"

    await_timeout = coerce_float(await_timeout_raw, 6.0)

    return SimulatorOptions(
        request_id=request_id,
        mission_label=mission_label,
        mission_number=mission_number,
        direction=direction,
        includes_ammo=bool(includes_ammo),
        site=site,
        simulate_cfg=simulate_cfg,
        await_user=bool(await_enabled),
        await_stage=await_stage,
        await_timeout=await_timeout,
        await_message=str(await_message),
    )


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AAMS 로봇/레일 모의 실행기")
    parser.add_argument("--mission", help="미션 번호 (1 또는 2)")
    parser.add_argument("--mission-label", help="미션/보관함 레이블")
    parser.add_argument("--direction", help="불입(in) 또는 불출(out)")
    parser.add_argument("--with-mag", action="store_true", help="탄창 포함 여부")
    parser.add_argument("--expected-qr", help="호환성용 인자 — 사용되지 않음")
    parser.add_argument("--bridge-mode", action="store_true", help="브릿지 모드 (호환성용)")
    parser.add_argument("--auto", action="store_true", help="자동 실행 모드 (호환성용)")
    parser.add_argument("--request-id", help="요청 ID")
    parser.add_argument("--site", help="사이트 식별자")
    parser.add_argument("--simulate", help="시뮬레이션 동작을 제어할 JSON 문자열")
    parser.add_argument("--await-user", action="store_true", dest="await_user", help="사용자 인터랙션 요청 이벤트 강제 활성화")
    parser.add_argument(
        "--await-user-auto",
        action="store_true",
        help="요청 방향에 따라 적절한 단계에서 await_user 이벤트 자동 발생",
    )
    parser.add_argument("--await-stage", help="await_user 이벤트를 발생시킬 스테이지")
    parser.add_argument("--await-timeout", help="await_user 응답 대기 시간(초)")
    parser.add_argument("--await-message", help="await_user 이벤트 메시지")
    args, extras = parser.parse_known_args(argv)
    if extras:
        setattr(args, "_extras", extras)
    else:
        setattr(args, "_extras", [])
    return args


def run_simulation(options: SimulatorOptions, listener: CommandStream) -> int:
    emitter = EventEmitter(options)
    listener.start()
    emitter.progress("starting", f"요청 {options.request_id or '-'} 장비 명령 준비")
    simulate_delay("starting", options.simulate_cfg)

    stages = STAGES_DISPATCH if options.mode == "dispatch" else STAGES_RETURN

    try:
        for stage, message in stages:
            for command in listener.drain():
                handle_command(command, emitter=emitter, current_stage=stage, pending_token=None)
            check_for_failure(stage, options.simulate_cfg)
            emitter.progress(stage, message)
            simulate_delay(stage, options.simulate_cfg)
            if options.await_user and options.await_stage and stage == options.await_stage:
                token = emitter.await_user(stage, options.await_message)
                wait_for_ack(listener, emitter, stage, token, options.await_timeout)
                emitter.await_user_done(stage, "사용자 확인 완료", token)
            if options.mode == "return" and stage == "verify":
                run_vision_checks(emitter, options.simulate_cfg)
    except SimulationAbort as exc:
        emitter.complete("error", stage, str(exc), error=str(exc))
        return 2
    except RuntimeError as exc:
        emitter.complete("error", stage, str(exc), error=str(exc))
        return 2

    emitter.complete("success", "complete", "장비 동작 시뮬레이션 완료")
    return 0

def main(argv: Optional[Iterable[str]] = None) -> int:
    args = parse_args(argv)
    listener = CommandStream()
    listener.start()
    payload = listener.initial_payload()
    options = build_simulator_options(args, payload)
    try:
        return run_simulation(options, listener)
    finally:
        listener.stop()


if __name__ == "__main__":
    sys.exit(main())