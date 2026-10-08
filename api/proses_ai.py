# ============================================================
# IMPORT LIBRARIES
# ============================================================

import asyncio
import time

from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="Security Monitoring AI API",
    description="Asynchronous AI Threat Analysis API",
    version="1.0.0"
)


# ============================================================
# MODEL A - RANDOM FOREST
# ============================================================

async def simulate_random_forest(input_text: str) -> dict:
    """
    Simulasi model Random Forest.
    Delay 0.3 detik.
    """

    await asyncio.sleep(0.3)

    threat_keywords = [
        "sql injection",
        "xss",
        "malware",
        "ransomware",
        "brute force",
        "ddos",
        "phishing"
    ]

    text = input_text.lower()

    is_threat = any(
        keyword in text
        for keyword in threat_keywords
    )

    if is_threat:
        prediction = "bahaya"
        confidence = 0.94
    else:
        prediction = "aman"
        confidence = 0.91

    return {
        "model": "rf",
        "prediction": prediction,
        "confidence": confidence
    }


# ============================================================
# MODEL B - SVM
# ============================================================

async def simulate_svm(input_text: str) -> dict:
    """
    Simulasi model SVM.
    Delay 0.5 detik.
    """

    await asyncio.sleep(0.5)

    threat_keywords = [
        "sql injection",
        "xss",
        "malware",
        "ransomware",
        "brute force",
        "ddos",
        "phishing"
    ]

    text = input_text.lower()

    is_threat = any(
        keyword in text
        for keyword in threat_keywords
    )

    if is_threat:
        prediction = "bahaya"
        confidence = 0.89
    else:
        prediction = "aman"
        confidence = 0.93

    return {
        "model": "svm",
        "prediction": prediction,
        "confidence": confidence
    }


# ============================================================
# API ENDPOINT
# GET /api/proses_ai?input=<data_teks>
# ============================================================

@app.get("/api/proses_ai")
async def proses_ai(
    input: str = Query(
        ...,
        description="Data teks ancaman yang akan dianalisis"
    )
):

    try:

        if not input.strip():
            return JSONResponse(
                status_code=400,
                content={
                    "status": "error",
                    "duration_seconds": 0.0,
                    "results": [],
                    "error": "Parameter input tidak boleh kosong"
                }
            )

        # Mulai menghitung waktu
        start_time = time.perf_counter()

        # Jalankan kedua model secara bersamaan
        rf_result, svm_result = await asyncio.gather(
            simulate_random_forest(input),
            simulate_svm(input)
        )

        # Selesai menghitung waktu
        end_time = time.perf_counter()

        duration_seconds = round(
            end_time - start_time,
            4
        )

        return {
            "status": "success",
            "duration_seconds": duration_seconds,
            "results": [
                rf_result,
                svm_result
            ]
        }

    except Exception as error:

        end_time = time.perf_counter()

        duration_seconds = round(
            end_time - start_time,
            4
        ) if "start_time" in locals() else 0.0

        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "duration_seconds": duration_seconds,
                "results": [],
                "error": str(error)
            }
        )