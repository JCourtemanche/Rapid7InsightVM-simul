#!/bin/bash
# Cloud Run deployment script for the Rapid7 Nexpose API simulator.
# Usage: bash deploy-cloudrun.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
REGION="europe-west1"
SERVICE_NAME="rapid7-nexpose-simulator"
REPO_NAME="rapid7-nexpose-simulator"

NEXPOSE_USERNAME="${NEXPOSE_USERNAME:-nxadmin}"
NEXPOSE_PASSWORD="${NEXPOSE_PASSWORD:-nxadmin-secret}"

echo -e "${GREEN}=== Cloud Run deployment - Rapid7 Nexpose Simulator ===${NC}\n"
echo -e "${YELLOW}Project:${NC} $PROJECT_ID"
echo -e "${YELLOW}Region:${NC}  $REGION"
echo -e "${YELLOW}Service:${NC} $SERVICE_NAME"
echo ""

echo -e "${YELLOW}[1/6] Enabling APIs...${NC}"
gcloud services enable run.googleapis.com
gcloud services enable cloudbuild.googleapis.com
gcloud services enable artifactregistry.googleapis.com
echo -e "${GREEN}OK - APIs enabled${NC}\n"

echo -e "${YELLOW}[2/6] Configuring Artifact Registry...${NC}"
REPO_EXISTS=$(gcloud artifacts repositories list \
  --location=$REGION \
  --filter="name:$REPO_NAME" \
  --format="value(name)" 2>/dev/null)

if [ -z "$REPO_EXISTS" ]; then
  gcloud artifacts repositories create $REPO_NAME \
    --repository-format=docker \
    --location=$REGION \
    --description="Rapid7 Nexpose API Simulator images" \
    --quiet
  echo -e "${GREEN}OK - Repository created${NC}"
else
  echo -e "${GREEN}OK - Repository already exists${NC}"
fi
echo ""

echo -e "${YELLOW}[3/6] Checking Dockerfile...${NC}"
if [ ! -f "deployment/Dockerfile" ]; then
    echo -e "${RED}ERROR: Dockerfile not found${NC}"
    exit 1
fi
echo -e "${GREEN}OK - Dockerfile found${NC}\n"

echo -e "${YELLOW}[4/6] Building Docker image...${NC}"
echo "This may take 2-3 minutes..."
gcloud builds submit --config cloudbuild.yaml

IMAGE_PATH="${REGION}-docker.pkg.dev/$PROJECT_ID/$REPO_NAME/rapid7-nexpose-simulator:latest"
echo -e "${GREEN}OK - Image built: $IMAGE_PATH${NC}\n"

echo -e "${YELLOW}[5/6] Deploying to Cloud Run...${NC}"
gcloud run deploy $SERVICE_NAME \
  --image $IMAGE_PATH \
  --platform managed \
  --region $REGION \
  --allow-unauthenticated \
  --memory 512Mi \
  --cpu 1 \
  --timeout 300 \
  --min-instances 0 \
  --max-instances 2 \
  --set-env-vars "NEXPOSE_USERNAME=${NEXPOSE_USERNAME},NEXPOSE_PASSWORD=${NEXPOSE_PASSWORD},DEBUG=False"

echo -e "${YELLOW}[6/6] Configuring public access...${NC}"
gcloud run services add-iam-policy-binding $SERVICE_NAME \
  --region=$REGION \
  --member=allUsers \
  --role=roles/run.invoker \
  --project=$PROJECT_ID \
  --quiet 2>/dev/null && PUBLIC_ACCESS=true || PUBLIC_ACCESS=false

if [ "$PUBLIC_ACCESS" = true ]; then
  echo -e "${GREEN}OK - Public access enabled${NC}\n"
else
  echo -e "${YELLOW}Warning: public access blocked by organisation policy${NC}\n"
fi

SERVICE_URL=$(gcloud run services describe $SERVICE_NAME \
  --region $REGION \
  --format 'value(status.url)')

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Deployment successful!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${YELLOW}Service URL:${NC} ${GREEN}$SERVICE_URL${NC}"
echo ""
echo -e "${YELLOW}Validation tests:${NC}"
echo ""
echo "1. Health check:"
echo -e "   ${GREEN}curl $SERVICE_URL/health${NC}"
echo ""
echo "2. Assets list:"
echo -e "   ${GREEN}curl -u ${NEXPOSE_USERNAME}:${NEXPOSE_PASSWORD} '$SERVICE_URL/api/3/assets?size=5'${NC}"
echo ""
echo "3. Sites list:"
echo -e "   ${GREEN}curl -u ${NEXPOSE_USERNAME}:${NEXPOSE_PASSWORD} '$SERVICE_URL/api/3/sites'${NC}"
echo ""
echo -e "${YELLOW}XSIAM configuration (Rapid7 Nexpose):${NC}"
echo "   Server URL: $SERVICE_URL"
echo "   Username:   ${NEXPOSE_USERNAME}"
echo "   Password:   ${NEXPOSE_PASSWORD}"
echo ""
echo -e "${YELLOW}Useful commands:${NC}"
echo "   View logs: gcloud run services logs read $SERVICE_NAME --region $REGION"
echo "   Delete:    gcloud run services delete $SERVICE_NAME --region $REGION"
echo ""
