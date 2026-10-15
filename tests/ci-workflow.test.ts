// biome-ignore-all lint/suspicious/noTemplateCurlyInString: GitHub Actions expressions are literal text in these assertions
import { expect, test } from "bun:test";
import { join } from "node:path";

const workflowPath = join(import.meta.dir, "../.github/workflows/ci.yml");

type Step = {
  uses?: string;
  run?: string;
  id?: string;
  with?: Record<string, string | boolean>;
};
type Job = {
  if?: string;
  needs?: string[];
  permissions?: Record<string, string>;
  steps: Step[];
};

async function workflow() {
  return Bun.file(workflowPath).text();
}

async function jobs(): Promise<Record<string, Job>> {
  return (Bun.YAML.parse(await workflow()) as { jobs: Record<string, Job> })
    .jobs;
}

function builds(job: Job): Step[] {
  return job.steps.filter((s) =>
    s.uses?.startsWith("docker/build-push-action@"),
  );
}

test("every action is pinned to a full commit SHA and no checkout keeps credentials", async () => {
  const contents = await workflow();
  for (const use of contents.matchAll(/uses: (\S+)/gu)) {
    expect(use[1]).toMatch(/@[0-9a-f]{40}$/u);
  }
  expect(contents).toContain("\npermissions: {}\n");
  const checkouts = contents.match(/actions\/checkout@/gu) ?? [];
  const persist = contents.match(/persist-credentials: false/gu) ?? [];
  expect(persist).toHaveLength(checkouts.length);
});

test("build-smoke loads both images into the daemon and hands exactly those tags to smoke.sh", async () => {
  const job = (await jobs())["build-smoke"];
  expect(job?.permissions).toEqual({ contents: "read" });
  expect(job?.steps.some((s) => s.with?.driver === "docker")).toBe(true);
  const [base, claude] = builds(job as Job);
  expect(base?.with?.push).toBe(false);
  expect(base?.with?.load).toBe(true);
  expect(claude?.with?.push).toBe(false);
  expect(claude?.with?.load).toBe(true);
  const baseTag = String(base?.with?.tags);
  const claudeTag = String(claude?.with?.tags);
  expect(String(claude?.with?.["build-args"]).trim()).toBe(
    `BASE_IMAGE=${baseTag}`,
  );
  const smoke = job?.steps.find((s) => s.run?.includes("smoke.sh"));
  expect(smoke?.run?.trim()).toBe(`./smoke.sh ${baseTag} ${claudeTag}`);
  expect(JSON.stringify(job)).not.toContain("login-action");
});

test("publish runs only on release tags, after check and build-smoke, and pins the Claude layer to the base digest", async () => {
  const job = (await jobs()).publish;
  expect(job?.if).toBe("startsWith(github.ref, 'refs/tags/v')");
  expect(job?.needs?.sort()).toEqual(["build-smoke", "check"]);
  expect(job?.permissions).toEqual({ contents: "write", packages: "write" });
  const [base, claude] = builds(job as Job);
  expect(base?.id).toBe("base");
  for (const step of [base, claude]) {
    expect(step?.with?.push).toBe(true);
    expect(step?.with?.platforms).toBe("linux/amd64,linux/arm64");
  }
  const baseTags = String(base?.with?.tags).trim().split("\n");
  const claudeTags = String(claude?.with?.tags).trim().split("\n");
  expect(baseTags).toEqual([
    "${{ env.IMAGE }}:base",
    "${{ env.IMAGE }}:base-${{ github.ref_name }}",
  ]);
  expect(claudeTags).toEqual([
    "${{ env.IMAGE }}:claude",
    "${{ env.IMAGE }}:claude-${{ github.ref_name }}",
  ]);
  expect(String(claude?.with?.["build-args"]).trim()).toBe(
    "BASE_IMAGE=${{ env.IMAGE }}@${{ steps.base.outputs.digest }}",
  );
  const login = job?.steps.find((s) =>
    s.uses?.startsWith("docker/login-action@"),
  );
  expect(login?.with?.password).toBe("${{ secrets.GITHUB_TOKEN }}");
  expect(login?.with?.registry).toBe("ghcr.io");
});

test("the image name is the one the README documents", async () => {
  const contents = await workflow();
  expect(contents).toContain("IMAGE: ghcr.io/hatchward/agent\n");
  const readme = await Bun.file(join(import.meta.dir, "../README.md")).text();
  expect(readme).toContain("`ghcr.io/hatchward/agent:base`");
  expect(readme).toContain("`ghcr.io/hatchward/agent:claude`");
});

test("publish creates the GitHub release from the notes file bin/release checks for", async () => {
  const job = (await jobs()).publish;
  const release = job?.steps.find((s) => s.run?.includes("gh release create"));
  expect(release?.run).toContain('test -s ".github/releases/${TAG}.md"');
  expect(release?.run).toContain("--verify-tag");
  expect(release?.run).toContain('--notes-file ".github/releases/${TAG}.md"');
  const script = await Bun.file(join(import.meta.dir, "../bin/release")).text();
  expect(script).toContain('notes_path=".github/releases/${tag}.md"');
  expect(script).toContain('REPO="hatchward/agent"');
  for (const job of ["check", "build-smoke"]) {
    expect(script).toContain(job);
  }
});
