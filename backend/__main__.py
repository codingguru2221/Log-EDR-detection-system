import logging

import uvicorn


if __name__ == "__main__":
    logging.basicConfig(
        filename="trinetra.log",
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=False)
