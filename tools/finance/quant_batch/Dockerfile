FROM public.ecr.aws/lambda/python:3.12
RUN pip install --no-cache-dir numpy scipy pandas statsmodels hmmlearn pyarrow boto3
COPY prism/ ${LAMBDA_TASK_ROOT}/prism/
COPY runner.py ${LAMBDA_TASK_ROOT}/
CMD ["runner.lambda_handler"]
