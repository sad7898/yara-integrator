FROM python:3.10-slim-buster
ENV YARA_VERSION 4.2.3
RUN apt-get update && apt-get install -y --no-install-recommends automake libtool make gcc pkg-config bison git unzip wget
RUN echo "Install Yara from source..." \
  && cd /tmp/ \
  && git clone --recursive --branch v$YARA_VERSION https://github.com/VirusTotal/yara.git \
  && cd /tmp/yara \
  && ./bootstrap.sh \
  && ./configure \
  && make \
  && make install \
  && rm -rf /tmp/yara

RUN echo "Installing dex2jar..."
RUN apt-get install -y openjdk-11-jdk-headless && \
    apt-get install -y wget && \
    wget https://github.com/pxb1988/dex2jar/releases/download/v2.1/dex2jar-2.1.zip && \
    unzip dex2jar-2.1.zip && \
    rm dex2jar-2.1.zip && \
    chmod +x /dex-tools-2.1/d2j-dex2jar.sh

RUN echo "Installing apktool..."

RUN mkdir /usr/local/bin/apktool && \
    wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.7.0.jar -O /usr/local/bin/apktool/apktool.jar && \
    wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O /usr/local/bin/apktool/apktool && \
    chmod +x /usr/local/bin/apktool/apktool.jar && \
    chmod +x /usr/local/bin/apktool/apktool

RUN echo "Cleaning up apt" && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Set environment variables
ENV JAVA_HOME /usr/lib/jvm/java-8-openjdk-amd64/
ENV PATH $PATH:/usr/local/bin/apktool
ENV PATH="/dex-tools-2.1:${PATH}"

WORKDIR /server
COPY ./requirements.txt /server
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
ENV FLASK_APP=app.py
CMD ["flask", "run", "--host", "0.0.0.0","--port","5000"]