# piigate container engine: Presidio Analyzer (Data Privacy Stack) + Polish spaCy model, built on YOUR machine.
#
# The image is never published: pl_core_news_lg is licensed GPL-3.0 (see README, "Model license"); you download it
# here, at build time, from explosion/spacy-models; URL and sha256 are in pl-model-requirements.txt and pip checks the
# hash. piigate itself stays MIT.
#
#   docker build -t piigate-presidio:2.2.366 docker/
#   docker run -d --name piigate-presidio --network none ...   # see README, "Container engine"
#
# Final stage is the distroless variant (no shell, no pip): the model is unpacked in a builder stage based on the
# regular image of the same release, then copied in. Both bases are pinned by digest.
ARG BUILDER=ghcr.io/data-privacy-stack/presidio-analyzer:2.2.366@sha256:036d2f9b3c274fb36497383acef8f2d5aea528a014801c2c3040fb067990c79c
ARG BASE=ghcr.io/data-privacy-stack/presidio-analyzer:2.2.366-distroless@sha256:84cb78c12a26d7ff4d2f5b980452dd9983c0a5c8c56ee410226bb6bb3f19f7d8

FROM ${BUILDER} AS model
COPY pl-model-requirements.txt /tmp/pl-model-requirements.txt
USER root
# pip downloads the wheel itself and refuses it unless its sha256 matches the requirements file (--require-hashes)
RUN pip install --require-hashes --no-deps --no-compile --target /out -r /tmp/pl-model-requirements.txt

FROM ${BASE}
COPY --from=model /out/ /usr/lib/python3.12/site-packages/
COPY analyzer.yaml /app/piigate/analyzer.yaml
ENV ANALYZER_CONF_FILE=/app/piigate/analyzer.yaml \
    NLP_CONF_FILE= \
    RECOGNIZER_REGISTRY_CONF_FILE=
