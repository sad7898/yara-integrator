import { useRouter } from "next/router";
import React, { useEffect, useState } from "react";
import styles from "@/styles/Home.module.css";
import { client } from "@/utils/axiosInstance";
import { Button } from "@/components/button";
import { Block } from "@/components/block";
import jsbeautifier from "js-beautify";

const Rule = () => {
  const router = useRouter();
  const { id } = router.query;
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [content, setContent] = useState("");
  const [error, setError] = useState("");

  const onSubmit = () => {
    const formData = new FormData();
    formData.append("name", name);
    formData.append(
      "content",
      jsbeautifier(content.replace(/(\r\n|\n|\r)/gm, ""))
    );
    if (id && !Array.isArray(id)) {
      client
        .put(`/yara/${encodeURI(id)}`, formData)
        .then((res) => {
          if (res.data.success) router.push("/rules");
          else setError("Something went wrong, please try submitting again.");
        })
        .catch((err) => {
          setError(err?.response?.data?.error);
        });
    }
  };
  const fetchRule = async (id: string) => {
    const { data } = await client.get(`/yara/${encodeURI(id)}`);
    if (data.data) {
      setName(data.data.name);
      setContent(data.data.content);
      setDescription(data.data.description);
    }
  };
  useEffect(() => {
    if (id && id.length > 0) {
      if (Array.isArray(id)) fetchRule(id[0]);
      else fetchRule(id);
    }
  }, [id]);
  return (
    <main
      className={`${styles.main} bg-bg flex flex-col items-center justify-center`}
    >
      <Block className="flex flex-col text-black gap-y-5">
        <h1 className="font-bold text-3xl">Edit</h1>
        <div className="flex flex-col">
          <label>Name</label>
          <input
            type="text"
            className="border p-2"
            value={name}
            required
            onChange={(e) => setName(e.target.value)}
          ></input>
          <label>Description</label>
          <textarea
            className="border w-full min-h-[100px] px-1 py-1"
            required
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </div>

        <div className="flex flex-col">
          <label>Content</label>
          <textarea
            className="border w-full min-h-[450px] px-1 py-1"
            value={content}
            required
            onChange={(e) => setContent(e.target.value)}
          ></textarea>
        </div>
        <div className="text-red-500">{error}</div>
        <div className="flex flex-row gap-x-2">
          <Button onClick={onSubmit} variant="primary">
            Save
          </Button>
          <Button variant="secondary" onClick={() => router.replace("/rules")}>
            Cancel
          </Button>
        </div>
      </Block>
    </main>
  );
};

export default Rule;
