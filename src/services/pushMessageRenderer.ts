import type { NotificationEventType } from "../repositories/notificationRepository";

type Copy = {
  title: string;
  someone: string;
  postCommented: string;
  commentReplied: string;
  postLiked: string;
  postLikedMany: (count: number) => string;
  commentLiked: string;
  commentLikedMany: (count: number) => string;
};

const copies: Record<string, Copy> = {
  en: {
    title: "CivicOS",
    someone: "Someone",
    postCommented: "{actor} commented on your post.",
    commentReplied: "{actor} replied to your comment.",
    postLiked: "{actor} liked your post.",
    postLikedMany: (count) => `Your post received ${count} new likes.`,
    commentLiked: "{actor} liked your comment.",
    commentLikedMany: (count) => `Your comment received ${count} new likes.`,
  },
  sv: {
    title: "CivicOS",
    someone: "Någon",
    postCommented: "{actor} kommenterade ditt inlägg.",
    commentReplied: "{actor} svarade på din kommentar.",
    postLiked: "{actor} gillade ditt inlägg.",
    postLikedMany: (count) => `Ditt inlägg fick ${count} nya gilla-markeringar.`,
    commentLiked: "{actor} gillade din kommentar.",
    commentLikedMany: (count) => `Din kommentar fick ${count} nya gilla-markeringar.`,
  },
  de: {
    title: "CivicOS",
    someone: "Jemand",
    postCommented: "{actor} hat deinen Beitrag kommentiert.",
    commentReplied: "{actor} hat auf deinen Kommentar geantwortet.",
    postLiked: "{actor} gefällt dein Beitrag.",
    postLikedMany: (count) => `Dein Beitrag hat ${count} neue Likes erhalten.`,
    commentLiked: "{actor} gefällt dein Kommentar.",
    commentLikedMany: (count) => `Dein Kommentar hat ${count} neue Likes erhalten.`,
  },
  es: {
    title: "CivicOS",
    someone: "Alguien",
    postCommented: "{actor} comentó tu publicación.",
    commentReplied: "{actor} respondió a tu comentario.",
    postLiked: "A {actor} le gustó tu publicación.",
    postLikedMany: (count) => `Tu publicación recibió ${count} Me gusta nuevos.`,
    commentLiked: "A {actor} le gustó tu comentario.",
    commentLikedMany: (count) => `Tu comentario recibió ${count} Me gusta nuevos.`,
  },
  fr: {
    title: "CivicOS",
    someone: "Quelqu’un",
    postCommented: "{actor} a commenté votre publication.",
    commentReplied: "{actor} a répondu à votre commentaire.",
    postLiked: "{actor} a aimé votre publication.",
    postLikedMany: (count) => `Votre publication a reçu ${count} nouvelles mentions J’aime.`,
    commentLiked: "{actor} a aimé votre commentaire.",
    commentLikedMany: (count) => `Votre commentaire a reçu ${count} nouvelles mentions J’aime.`,
  },
  fa: {
    title: "CivicOS",
    someone: "یک نفر",
    postCommented: "{actor} روی پست شما نظر داد.",
    commentReplied: "{actor} به نظر شما پاسخ داد.",
    postLiked: "{actor} پست شما را پسندید.",
    postLikedMany: (count) => `پست شما ${count} پسند جدید گرفت.`,
    commentLiked: "{actor} نظر شما را پسندید.",
    commentLikedMany: (count) => `نظر شما ${count} پسند جدید گرفت.`,
  },
  ar: {
    title: "CivicOS",
    someone: "شخص ما",
    postCommented: "علّق {actor} على منشورك.",
    commentReplied: "ردّ {actor} على تعليقك.",
    postLiked: "أعجب {actor} بمنشورك.",
    postLikedMany: (count) => `حصل منشورك على ${count} إعجابات جديدة.`,
    commentLiked: "أعجب {actor} بتعليقك.",
    commentLikedMany: (count) => `حصل تعليقك على ${count} إعجابات جديدة.`,
  },
  ja: {
    title: "CivicOS",
    someone: "誰か",
    postCommented: "{actor}さんがあなたの投稿にコメントしました。",
    commentReplied: "{actor}さんがあなたのコメントに返信しました。",
    postLiked: "{actor}さんがあなたの投稿に「いいね」しました。",
    postLikedMany: (count) => `あなたの投稿に新しい「いいね」が${count}件あります。`,
    commentLiked: "{actor}さんがあなたのコメントに「いいね」しました。",
    commentLikedMany: (count) => `あなたのコメントに新しい「いいね」が${count}件あります。`,
  },
  zh: {
    title: "CivicOS",
    someone: "有人",
    postCommented: "{actor}评论了你的帖子。",
    commentReplied: "{actor}回复了你的评论。",
    postLiked: "{actor}赞了你的帖子。",
    postLikedMany: (count) => `你的帖子收到了 ${count} 个新赞。`,
    commentLiked: "{actor}赞了你的评论。",
    commentLikedMany: (count) => `你的评论收到了 ${count} 个新赞。`,
  },
};

export const normalizeNotificationLocale = (locale: string | null): string => {
  const base = (locale || "en").trim().toLowerCase().split(/[-_]/u)[0];
  return copies[base] ? base : "en";
};

export const renderPushMessage = (input: {
  eventType: NotificationEventType;
  aggregationCount: number;
  locale: string | null;
  actorPublicNickname?: unknown;
}) => {
  const copy = copies[normalizeNotificationLocale(input.locale)];
  const actor =
    typeof input.actorPublicNickname === "string" &&
    input.actorPublicNickname.trim()
      ? input.actorPublicNickname.trim()
      : copy.someone;
  const count = Math.max(1, Math.trunc(input.aggregationCount) || 1);

  let body: string;
  switch (input.eventType) {
    case "discussion.post_commented":
      body = copy.postCommented.replace("{actor}", actor);
      break;
    case "discussion.comment_replied":
      body = copy.commentReplied.replace("{actor}", actor);
      break;
    case "discussion.post_liked":
      body = count > 1
        ? copy.postLikedMany(count)
        : copy.postLiked.replace("{actor}", actor);
      break;
    case "discussion.comment_liked":
      body = count > 1
        ? copy.commentLikedMany(count)
        : copy.commentLiked.replace("{actor}", actor);
      break;
  }

  return { title: copy.title, body };
};

export default renderPushMessage;
