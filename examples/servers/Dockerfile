FROM python:3.12.12-slim-trixie
# FastMCP 4 serves both supported protocol versions; the older-only server
# builds with FASTMCP=fastmcp==2.14.7.
ARG FASTMCP=fastmcp==4.2.5
RUN pip install --no-cache-dir "$FASTMCP"
COPY server.py /app/server.py
USER 65532
EXPOSE 8000
ENTRYPOINT ["python", "/app/server.py"]
