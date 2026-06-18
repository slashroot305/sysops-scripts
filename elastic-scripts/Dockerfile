FROM public.ecr.aws/lambda/python:3.11

RUN yum update -y && yum clean all

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY create_agent_health_dashboard.py .
COPY lambda_handler.py .

CMD ["lambda_handler.handler"]
