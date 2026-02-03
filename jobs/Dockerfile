FROM public.ecr.aws/docker/library/python:3.11-slim

WORKDIR /app
COPY libs libs
COPY jobs/runner.py runner.py

RUN pip install --no-cache-dir PyYAML==6.0.1

CMD ["python", "runner.py"]
