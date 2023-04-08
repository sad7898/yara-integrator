import { Block } from "@/components/block";
import { Button } from "@/components/button";
import styles from "@/styles/Home.module.css";
import { client } from "@/utils/axiosInstance";
import { useRouter } from "next/router";
import { ChangeEvent, useState } from "react";

const Setting = () => {
  const router = useRouter();
  const [mobSfUrl, setMobSfUrl] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [error, setError] = useState("");
  const handleMobSfUrlChange = (event: ChangeEvent<HTMLInputElement>) => {
    if (!isValidUrl(event.target.value)) setError("URL is not valid");
    else setError("");
    setMobSfUrl(event.target.value);
  };

  const handleApiKeyChange = (event: ChangeEvent<HTMLInputElement>) => {
    setApiKey(event.target.value);
  };
  const isValidUrl = (url: string) => {
    try {
      new URL(url);
      return true;
    } catch (err) {
      return false;
    }
  };
  const handleSubmit = () => {
    const formData = new FormData();
    formData.append("url", mobSfUrl);
    formData.append("apiKey", apiKey);
    client
      .post("/mobsf-api/config", formData)
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
        </div>
        <div>
          <Button className="max-w-[172px]" onClick={handleSubmit}>
            Save
          </Button>
        </div>
        {error && <div className="text-red-500">{error}</div>}
      </Block>
    </main>
  );
};

export default Setting;
