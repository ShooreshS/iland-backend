import OpenAI from "openai";

const apiKey = process.env.OPENAI_API_KEY;

if (!apiKey) {
  console.error("OPENAI_API_KEY is not set. Add it to back/.env or export it before running this script.");
  process.exit(1);
}

const openai = new OpenAI({
  apiKey,
});

try {
  const response = await openai.moderations.create({
    model: "omni-moderation-latest",
    input: "Should the municipality extend public-library opening hours?",
  });

  const result = response.results[0];

  console.log("Moderation API key works.");
  console.log("Model:", response.model);
  console.log("Flagged:", result?.flagged ?? false);
  console.log("Categories:", result?.categories ?? {});
} catch (error) {
  if (error instanceof OpenAI.APIError) {
    console.error("OpenAI API request failed.");
    console.error("Status:", error.status);
    console.error("Request ID:", error.requestID ?? "unknown");
    console.error("Type:", error.type ?? "unknown");
    console.error("Code:", error.code ?? "unknown");
    console.error("Message:", error.message);

    if (error.status === 429) {
      console.error(
        "This key was accepted, but the OpenAI project/org is currently rate-limited or has insufficient quota.",
      );
    }

    process.exit(1);
  }

  throw error;
}
