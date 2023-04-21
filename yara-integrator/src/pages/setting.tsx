import { Block } from "@/components/block";
import { Button } from "@/components/button";
import styles from "@/styles/Home.module.css";
import { client } from "@/utils/axiosInstance";
import { useRouter } from "next/router";
import { ChangeEvent, useEffect, useState } from "react";

const Setting = () => {
  const router = useRouter();
  const [mobSfUrl, setMobSfUrl] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [shouldDecompile, setShouldDecompile] = useState<Boolean>();
  const [shouldUseMobSf, setShouldUseMobSf] = useState<Boolean>();
  const [error, setError] = useState("");
  useEffect(() => {
    client.get("/config").then(({ data }) => {
      setMobSfUrl(data.MOBSF_URL ?? "");
      setShouldDecompile(!!data.SHOULD_DECOMPILE);
      setShouldUseMobSf(!!data.SHOULD_USE_MOBSF);
    });
  }, []);
  const handleMobSfUrlChange = (event: ChangeEvent<HTMLInputElement>) => {
    if (!isValidUrl(event.target.value)) setError("URL is not valid");
    else setError("");
    setMobSfUrl(event.target.value);
  };

  const handleApiKeyChange = (event: ChangeEvent<HTMLInputElement>) => {
    setApiKey(event.target.value);
  };
  const isValidUrl = (url: string) => {
    if (url.length === 0) return true;
    try {
      new URL(url);
      return true;
    } catch (err) {
      return false;
    }
  };
  const handleSubmit = () => {
    const formData = new FormData();
    formData.append("MOBSF_URL", mobSfUrl);
    formData.append("MOBSF_API_KEY", apiKey);
    formData.append("SHOULD_DECOMPILE", shouldDecompile ? "true" : "false");
    formData.append("SHOULD_USE_MOBSF", shouldUseMobSf ? "true" : "false");
    client
      .post("/config", formData)
      .then((res) => {
        router.push("/");
      })
      .catch((err) => {
        setError(err?.response?.data);
      });
  };
  return (
    <main
      className={
        styles.main + " bg-bg flex flex-col items-center justify-center"
      }
    >
      <Block className="flex flex-col text-black gap-y-5">
        <div>
          <h1 className="font-bold text-3xl">Scan Config</h1>
          <div className="flex flex-col gap-y-3 mt-2 mb-3">
            <label>
              <input
                className="mr-2"
                type="checkbox"
                checked={!!shouldDecompile}
                onChange={() => setShouldDecompile((prev) => !prev)}
              />
              Decompile APK to JAR during scan
            </label>
            <label>
              <input
                className="mr-2"
                type="checkbox"
                checked={!!shouldUseMobSf}
                onChange={() => setShouldUseMobSf((prev) => !prev)}
              />
              Enable Static Analysis with MobSF
            </label>
          </div>
        </div>
        <div>
          <h1 className="font-bold text-3xl">MobSF API Config</h1>
          <div className="flex flex-col gap-y-3 mt-2 mb-8">
            <label>URL</label>
            <input
              type="text"
              className="border p-2"
              placeholder="http://localhost:3000"
              value={mobSfUrl}
              onChange={handleMobSfUrlChange}
            ></input>
            <label>API KEY</label>
            <input
              type="password"
              className="border p-2"
              required
              value={apiKey}
              onChange={handleApiKeyChange}
            />
            <div className="text-slate-500">
              {
                "*MobSF API Key can be obtained from log of MobSF's host machine"
              }
            </div>
            <div className="text-slate-500">
              {
                '*If MobSF is hosted on local machine, use domain name as "host.docker.internal" instead of "localhost"'
              }
            </div>
          </div>
        </div>
        <div>
          <Button
            className="max-w-[172px]"
            onClick={handleSubmit}
            disabled={!!error}
          >
            Save
          </Button>
        </div>
        {error && <div className="text-red-500">{error}</div>}
      </Block>
    </main>
  );
};

export default Setting;
