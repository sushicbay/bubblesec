import os
import shutil
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import runner

UPLOAD_DIR = "./uploaded_pcaps"

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/run")
def run():
    processed_files, alerts_by_file = runner.main()

    if not processed_files:
        message = "Request Completed. No files were processed."
    else:
        formatted = "\n- ".join(processed_files)
        message = (
            "Request Completed.\n"
            "The following files were processed:\n- " + formatted
        )

    return {
        "message": message,
        "files_processed": processed_files,
        "alerts": alerts_by_file
    }


@app.post("/upload")
async def upload_files(files: list[UploadFile] = File(...)):
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    saved_files = []

    for file in files:
        file_path = os.path.join(UPLOAD_DIR, file.filename)

        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        saved_files.append(file.filename)

    return {"uploaded_files": saved_files}