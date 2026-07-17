export const GATE0_TEXT_LIMITS = Object.freeze({
  titleMaxLength: 280,
  bodyMaxLength: 5_000,
  pollQuestionMaxLength: 500,
  pollOptionMaxLength: 500,
  imageAltTextMaxLength: 1_000,
});

export const GATE0_IMAGE_LIMITS = Object.freeze({
  maxImageBytes: 5 * 1024 * 1024,
  allowedMimeTypes: ["image/jpeg", "image/png", "image/webp", "image/gif"],
});

export type Gate0ImageInput = {
  imageUrl?: string | null;
  mimeType?: string | null;
  sizeBytes?: number | null;
  altText?: string | null;
};

export type Gate0PostInput = {
  title?: string | null;
  body?: string | null;
  pollQuestion?: string | null;
  pollOptions?: string[];
  image?: Gate0ImageInput | null;
};

export type Gate0ValidationResult =
  | {
      ok: true;
    }
  | {
      ok: false;
      reasonCode:
        | "EMPTY_CONTENT"
        | "TEXT_TOO_LONG"
        | "IMAGE_METADATA_REQUIRED"
        | "IMAGE_URL_INVALID"
        | "IMAGE_TYPE_UNSUPPORTED"
        | "IMAGE_SIZE_INVALID"
        | "IMAGE_TOO_LARGE";
      message: string;
    };

const normalizeText = (value: string | null | undefined): string =>
  typeof value === "string" ? value.trim() : "";

const hasTextContent = (input: Gate0PostInput): boolean =>
  Boolean(
    normalizeText(input.title) ||
      normalizeText(input.body) ||
      normalizeText(input.pollQuestion) ||
      (input.pollOptions || []).some((option) => normalizeText(option)),
  );

const hasImageContent = (image: Gate0ImageInput | null | undefined): boolean =>
  Boolean(
    normalizeText(image?.imageUrl) ||
      normalizeText(image?.mimeType) ||
      normalizeText(image?.altText) ||
      image?.sizeBytes !== undefined,
  );

const validateLength = (
  label: string,
  value: string | null | undefined,
  maxLength: number,
): Gate0ValidationResult | null => {
  if (normalizeText(value).length <= maxLength) {
    return null;
  }

  return {
    ok: false,
    reasonCode: "TEXT_TOO_LONG",
    message: `${label} must be ${maxLength} characters or fewer.`,
  };
};

const validateHttpUrl = (value: string): boolean => {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" || parsed.protocol === "http:";
  } catch {
    return false;
  }
};

export const validateModerationGate0 = (
  input: Gate0PostInput,
): Gate0ValidationResult => {
  const image = input.image ?? null;
  if (!hasTextContent(input) && !hasImageContent(image)) {
    return {
      ok: false,
      reasonCode: "EMPTY_CONTENT",
      message: "Post content is required.",
    };
  }

  const lengthChecks: Array<[string, string | null | undefined, number]> = [
    ["Poll title", input.title, GATE0_TEXT_LIMITS.titleMaxLength],
    ["Poll body", input.body, GATE0_TEXT_LIMITS.bodyMaxLength],
    [
      "Poll question",
      input.pollQuestion,
      GATE0_TEXT_LIMITS.pollQuestionMaxLength,
    ],
    ["Image alt text", image?.altText, GATE0_TEXT_LIMITS.imageAltTextMaxLength],
  ];

  for (const [label, value, maxLength] of lengthChecks) {
    const result = validateLength(label, value, maxLength);
    if (result) {
      return result;
    }
  }

  for (const [index, option] of (input.pollOptions || []).entries()) {
    const result = validateLength(
      `Poll option ${index + 1}`,
      option,
      GATE0_TEXT_LIMITS.pollOptionMaxLength,
    );
    if (result) {
      return result;
    }
  }

  if (!hasImageContent(image)) {
    return { ok: true };
  }

  const imageUrl = normalizeText(image?.imageUrl);
  const mimeType = normalizeText(image?.mimeType).toLowerCase();
  const sizeBytes = image?.sizeBytes;

  if (!imageUrl || !mimeType || sizeBytes === undefined || sizeBytes === null) {
    return {
      ok: false,
      reasonCode: "IMAGE_METADATA_REQUIRED",
      message: "Image URL, file type, and size are required.",
    };
  }

  if (!validateHttpUrl(imageUrl)) {
    return {
      ok: false,
      reasonCode: "IMAGE_URL_INVALID",
      message: "Image URL must be a valid HTTP or HTTPS URL.",
    };
  }

  if (!GATE0_IMAGE_LIMITS.allowedMimeTypes.includes(mimeType)) {
    return {
      ok: false,
      reasonCode: "IMAGE_TYPE_UNSUPPORTED",
      message: "Image file type is not supported.",
    };
  }

  if (!Number.isInteger(sizeBytes) || sizeBytes <= 0) {
    return {
      ok: false,
      reasonCode: "IMAGE_SIZE_INVALID",
      message: "Image size must be a positive whole number of bytes.",
    };
  }

  if (sizeBytes > GATE0_IMAGE_LIMITS.maxImageBytes) {
    return {
      ok: false,
      reasonCode: "IMAGE_TOO_LARGE",
      message: "Image file size must be 5 MB or smaller.",
    };
  }

  return { ok: true };
};
