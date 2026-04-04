FROM scratch

ARG TARGETPLATFORM

COPY $TARGETPLATFORM/zoneomatic /zoneomatic

EXPOSE 9999

ENTRYPOINT ["/zoneomatic"]
