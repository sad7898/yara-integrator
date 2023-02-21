import type { NextApiRequest, NextApiResponse } from "next";
import { spawn } from "child_process";
type Data = {
  props: string[];
};

export default function handler(
  req: NextApiRequest,
  res: NextApiResponse<Data>
) {
  const python = spawn("python", ["_external/yara.py"]);
  const dt: Data = {
    props: [],
  };
  python.stdout.on("data", (data) => {
    dt.props.push(data.toString());
  });
  python.stderr.on("data", (data) => {
    console.log(data.toString());
  });
  python.on("exit", (code) => {
    console.log(`python process exit with code ${code}`);
    res.status(200).json(dt);
  });
}
