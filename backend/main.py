from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sha256 import tree_reduce_parallel_trace  # Ensure this is the updated function
import hashlib

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class HashInput(BaseModel):
    input: str

@app.post("/api/hash")
async def generate_sha256(data: HashInput):
    default_iv = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]
    # Call the trace-enabled custom function.
    custom_result = tree_reduce_parallel_trace(data.input.encode(), default_iv)
    
    # Also compute the built‑in SHA‑256 hash.
    normal_hash = hashlib.sha256(data.input.encode()).hexdigest()
    
    return {
        "finalDigest": custom_result["finalDigest"],
        "trace": custom_result["trace"],
        "normalHash": normal_hash
    }
