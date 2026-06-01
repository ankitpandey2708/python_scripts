import asyncio
import json
import time
import sys
from datetime import datetime
from openai import AsyncOpenAI

# ====================== CONFIG ======================
TEST_LIMIT = 139                    # Set to 139 to test ALL models
MAX_TIMEOUT = 25                    # Hard timeout in seconds (recommended 20-28)
DELAY_BETWEEN_REQUESTS = 0.5        # Be gentle with the API
# ===================================================

_GREEN = "\033[92m" if sys.stdout.isatty() else ""
_YELLOW = "\033[93m" if sys.stdout.isatty() else ""
_RED = "\033[91m" if sys.stdout.isatty() else ""
_RESET = "\033[0m" if sys.stdout.isatty() else ""

async def test_model(client, model_id: str):
    start_time = time.time()
    try:
        # Hard timeout using asyncio
        response = await asyncio.wait_for(
            client.chat.completions.create(
                model=model_id,
                messages=[{"role": "user", "content": "Say hello in one short sentence."}],
                max_tokens=80,
                temperature=0.7,
            ),
            timeout=MAX_TIMEOUT
        )

        elapsed = time.time() - start_time
        choice = response.choices[0]
        content = choice.message.content or ""
        success = bool(content.strip())

        status = f"{_GREEN}✔ Success{_RESET}" if success else f"{_YELLOW}✘ Empty{_RESET}"
        print(f"[{elapsed:6.2f}s] {status} | {model_id} | finish: {choice.finish_reason}")

        return {
            "model": model_id,
            "latency": round(elapsed, 2),
            "success": success,
            "content_preview": content.strip()[:100],
            "finish_reason": choice.finish_reason
        }

    except asyncio.TimeoutError:
        elapsed = time.time() - start_time
        print(f"[{elapsed:6.2f}s] {_RED}✘ Hard Timeout{_RESET} | {model_id} (killed after {MAX_TIMEOUT}s)")
        return {"model": model_id, "latency": round(elapsed, 2), "success": False, "error": "HardTimeout"}

    except Exception as e:
        elapsed = time.time() - start_time
        err_name = type(e).__name__
        print(f"[{elapsed:6.2f}s] {_RED}✘ Error{_RESET}    | {model_id} → {err_name}")
        return {"model": model_id, "latency": round(elapsed, 2), "success": False, "error": err_name}


async def benchmark_all():
    client = AsyncOpenAI(
        base_url="https://integrate.api.nvidia.com/v1",
        api_key=""
    )

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Fetching model list...")
    models = await client.models.list()
    model_list = [m.id for m in models.data]

    print(f"{_GREEN}✔ Found {len(model_list)} models. Starting benchmark...{_RESET}\n")

    results = []
    for i, model_id in enumerate(model_list[:TEST_LIMIT], 1):
        print(f"[{i:3d}/{min(TEST_LIMIT, len(model_list))}] ", end="")
        
        # Skip obvious non-chat models
        lower_id = model_id.lower()
        if any(x in lower_id for x in ["embed", "vision", "audio", "image", "tts", "stt", "whisper", "bge"]):
            print(f"{_YELLOW}Skipped (non-text model){_RESET}")
            continue

        result = await test_model(client, model_id)
        results.append(result)

        await asyncio.sleep(DELAY_BETWEEN_REQUESTS)   # Avoid hammering the API

    # ===================== SUMMARY =====================
    print("\n" + "="*90)
    print("FINAL BENCHMARK SUMMARY")
    print("="*90)

    successful = [r for r in results if r.get("success", False)]
    
    print(f"Models tested     : {len(results)}")
    print(f"Successfully working : {len(successful)}")
    print(f"Failed / Timed out   : {len(results) - len(successful)}\n")

    if successful:
        print(f"{_GREEN}Top 15 Fastest Working Models:{_RESET}")
        top_fast = sorted(successful, key=lambda x: x["latency"])[:15]
        for r in top_fast:
            preview = r.get("content_preview", "")[:60]
            print(f"  {r['latency']:6.2f}s  →  {r['model']}")
            if preview:
                print(f"           └─ \"{preview}\"")

    # Save results
    with open("nvidia_nim_full_benchmark.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"\nFull results saved to: nvidia_nim_full_benchmark.json")

if __name__ == "__main__":
    asyncio.run(benchmark_all())
