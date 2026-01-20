FROM python:3.11-slim
WORKDIR /work
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY demo.py ./demo.py
COPY data ./data
CMD ["python", "demo.py", "--mode", "with_atf"]
