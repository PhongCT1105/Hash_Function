from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import hashlib

app = FastAPI()

# Allow CORS for frontend on Vite (default port is 5173)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # or "*" for all origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Define request body schema
class HashInput(BaseModel):
    input: str

# Define SHA-256 endpoint
@app.post("/api/hash")
async def generate_sha256(data: HashInput):
    sha256_hash = hashlib.sha256(data.input.encode()).hexdigest()
    return {"hash": sha256_hash}
