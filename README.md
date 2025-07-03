# Get started with Truv MCP

1. Clone the repository
```shell
git clone https://github.com/truvhq/truv-mcp-server.git
```

2. Open `truv-mcp-server` directory and create `.env` file:
```shell
cd truv-mcp-server
make env
```

3. Update the values in `.env` file by adding in your Client ID and Sandbox Access key:
```
# please set your <Client ID>
API_CLIENT_ID=

# please set your <Access key>
API_SECRET=


4. Run the MCP server:
uv run --project . mcp run server.py


## Docker setup

1. Authenticate Docker to your ECR registry:

```bash
aws ecr get-login-password --region us-west-2 | docker login --username AWS --password-stdin 666209742092.dkr.ecr.us-west-2.amazonaws.com
```

2. Build and tag Docker image for ECR:

```bash
docker buildx build --platform linux/amd64 -f docker/Dockerfile \
  -t 666209742092.dkr.ecr.us-west-2.amazonaws.com/my-truv:mcp-v0.0.1 \
  .
```

3. Push the image to ECR:

```bash
docker push 666209742092.dkr.ecr.us-west-2.amazonaws.com/my-truv:mcp-v0.0.1
```


