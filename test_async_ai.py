import asyncio
import time
import httpx
import pytest

from api.proses_ai import app, simulate_random_forest, simulate_svm, analyze_nvidia_nim


# ============================================================
# TEST 1: DIRECT ASYNC CONCURRENCY TEST (RF + SVM)
# ============================================================

@pytest.mark.asyncio
async def test_concurrency_execution():
    """
    Menguji bahwa simulasi Random Forest (0.3s) dan SVM (0.5s)
    berjalan secara asynchronous (paralel) menggunakan asyncio.gather.
    Total durasi harus mendekati 0.5s, BUKAN 0.8s (sekuensial).
    """
    start_time = time.perf_counter()

    rf_result, svm_result = await asyncio.gather(
        simulate_random_forest("SQL Injection detected"),
        simulate_svm("SQL Injection detected")
    )

    elapsed = time.perf_counter() - start_time

    assert rf_result["model"] == "rf"
    assert rf_result["prediction"] == "bahaya"
    assert rf_result["confidence"] > 0.90

    assert svm_result["model"] == "svm"
    assert svm_result["prediction"] == "bahaya"
    assert svm_result["confidence"] > 0.80

    # Batas toleransi: harus < 0.65 detik (jauh di bawah 0.8s)
    assert elapsed < 0.65, f"Concurrency gagal: durasi {elapsed:.4f}s (harus < 0.65s)"
    assert elapsed >= 0.45, f"Durasi tidak wajar: {elapsed:.4f}s"
    print(f"\n[PASS] Concurrency execution (RF + SVM) verified: {elapsed:.4f} seconds")


# ============================================================
# TEST 2: FASTAPI ENDPOINT - THREAT INPUT
# ============================================================

@pytest.mark.asyncio
async def test_endpoint_threat_input():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/proses_ai", params={"input": "SQL Injection attempt detected"})

    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "success"
    assert "duration_seconds" in data
    assert data["duration_seconds"] < 0.65
    assert len(data["results"]) == 2

    models = {res["model"]: res for res in data["results"]}
    assert "rf" in models
    assert "svm" in models
    assert models["rf"]["prediction"] == "bahaya"
    assert models["svm"]["prediction"] == "bahaya"
    print(f"[PASS] Endpoint threat detected successfully. Latency: {data['duration_seconds']}s")


# ============================================================
# TEST 3: FASTAPI ENDPOINT - BENIGN INPUT
# ============================================================

@pytest.mark.asyncio
async def test_endpoint_benign_input():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/proses_ai", params={"input": "Laporan operasional rutin server aman"})

    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "success"
    for res in data["results"]:
        assert res["prediction"] == "aman"
    print(f"[PASS] Endpoint benign input classified as 'aman'. Latency: {data['duration_seconds']}s")


# ============================================================
# TEST 4: FASTAPI ENDPOINT - EMPTY INPUT VALIDATION
# ============================================================

@pytest.mark.asyncio
async def test_endpoint_empty_input():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/proses_ai", params={"input": "   "})

    assert response.status_code == 400
    data = response.json()
    assert data["status"] == "error"
    assert "tidak boleh kosong" in data["error"]
    print("[PASS] Empty input validation correctly returned HTTP 400")


# ============================================================
# TEST 5: FASTAPI ENDPOINT - MISSING PARAMETER
# ============================================================

@pytest.mark.asyncio
async def test_endpoint_missing_parameter():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/proses_ai")

    assert response.status_code == 422
    print("[PASS] Missing parameter validation correctly returned HTTP 422")


# ============================================================
# TEST 6: NVIDIA NIM - MODE 1: FAST INFERENCE
# ============================================================

@pytest.mark.asyncio
async def test_nvidia_nim_mode_fast():
    """
    Menguji NVIDIA NIM Mode Fast: Klasifikasi ancaman cepat dan penentuan skor risiko.
    """
    nim_res = await analyze_nvidia_nim("SQL Injection on users table", mode="fast")

    assert nim_res["mode"] == "fast"
    assert nim_res["verdict"] == "bahaya"
    assert "SQL" in nim_res["threat_category"]
    assert nim_res["severity"] in ["CRITICAL", "HIGH"]
    assert "tactical_summary" in nim_res
    assert nim_res["confidence"] > 0.85
    print(f"[PASS] NVIDIA NIM Mode Fast verified: {nim_res['threat_category']} ({nim_res['severity']})")


# ============================================================
# TEST 7: NVIDIA NIM - MODE 2: DEEP FORENSIC REASONING
# ============================================================

@pytest.mark.asyncio
async def test_nvidia_nim_mode_deep():
    """
    Menguji NVIDIA NIM Mode Deep: Analisis forensik mendalam, attack vector, dan langkah mitigasi taktis TNI.
    """
    nim_res = await analyze_nvidia_nim("Distributed Denial of Service SYN flood on database port 5432", mode="deep")

    assert nim_res["mode"] == "deep"
    assert nim_res["verdict"] == "bahaya"
    assert "DDoS" in nim_res["threat_category"] or "Denial" in nim_res["threat_category"]
    assert "attack_vector" in nim_res
    assert "forensic_details" in nim_res
    assert "mitigation_steps" in nim_res
    assert len(nim_res["mitigation_steps"]) >= 2
    print(f"[PASS] NVIDIA NIM Mode Deep verified: {nim_res['threat_category']} with {len(nim_res['mitigation_steps'])} mitigation steps")


# ============================================================
# TEST 8: INTEGRATED ENDPOINT WITH NVIDIA NIM & CONCURRENCY
# ============================================================

@pytest.mark.asyncio
async def test_endpoint_with_nim_integration():
    """
    Menguji pemanggilan endpoint dengan query param nim_mode='deep'.
    Memastikan Model A (RF), Model B (SVM), dan NIM dieksekusi secara harmonis.
    """
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/proses_ai", params={
            "input": "Ransomware payload attempting encryption of military database",
            "nim_mode": "deep"
        })

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "nim_analysis" in data
    assert data["nim_analysis"]["mode"] == "deep"
    assert data["nim_analysis"]["verdict"] == "bahaya"
    assert len(data["results"]) == 2
    assert data["consensus_verdict"] == "bahaya"
    print(f"[PASS] Integrated Endpoint (RF + SVM + NVIDIA NIM Deep) passed. Latency: {data['duration_seconds']}s")


# ============================================================
# CLI RUNNER WITH FORMATTED REPORT
# ============================================================

async def run_all_tests():
    print("=" * 70)
    print("  SUITE PENGUJIAN LENGKAP ASYNCHRONOUS AI & NVIDIA NIM - PaPK SIBER TNI")
    print("=" * 70)

    tests = [
        ("Concurrency Asynchronous (RF + SVM)", test_concurrency_execution),
        ("Endpoint Ancaman (SQL Injection)", test_endpoint_threat_input),
        ("Endpoint Lalu Lintas Normal (Benign)", test_endpoint_benign_input),
        ("Validasi Parameter Kosong (Empty Input)", test_endpoint_empty_input),
        ("Validasi Parameter Tidak Ada (Missing Param)", test_endpoint_missing_parameter),
        ("NVIDIA NIM Mode 1: Rapid Threat Classification (Fast)", test_nvidia_nim_mode_fast),
        ("NVIDIA NIM Mode 2: Deep Forensic Reasoning (Deep)", test_nvidia_nim_mode_deep),
        ("Integrasi Pipeline (RF + SVM + NVIDIA NIM Deep)", test_endpoint_with_nim_integration),
    ]

    passed = 0
    total = len(tests)

    for idx, (name, test_func) in enumerate(tests, 1):
        print(f"\n[{idx}/{total}] Menjalankan: {name}...")
        try:
            await test_func()
            passed += 1
        except Exception as e:
            print(f"❌ [FAIL] Error: {e}")

    print("\n" + "=" * 70)
    print(f"  HASIL PENGUJIAN: {passed}/{total} TEST BERHASIL (PASS)")
    print("=" * 70)

    if passed == total:
        print("  STATUS: SELURUH PENGUJIAN TAHAP 2 & TAHAP 3 DINYATAKAN LULUS (PASS).")
    else:
        print("  STATUS: ADA PENGUJIAN YANG GAGAL. PERIKSA LOG DI ATAS.")


if __name__ == "__main__":
    asyncio.run(run_all_tests())
