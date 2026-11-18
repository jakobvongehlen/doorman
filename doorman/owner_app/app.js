/* Doorman owner app. Everything is rendered as plain text: nothing from the agent or from
   third parties is ever inserted as HTML. (The only innerHTML is the constant icon set below.) */
"use strict";

const view = document.getElementById("view");
const tabs = document.getElementById("tabs");
const shell = document.getElementById("app");
const toasts = document.getElementById("toasts");

// ---------------------------------------------------------------- helpers

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === false || value === null || value === undefined) continue;
    if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
    else if (key === "class") el.className = value;
    else el.setAttribute(key, value === true ? "" : value);
  }
  for (const child of children.flat(Infinity)) {  // any depth: sections pass lists of lists
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

// One stroke icon set, 24px grid. Constants only.
const ICONS = {
  inbox: '<path d="M3 13h5l1.5 2.5h5L16 13h5"/><path d="M5.6 5h12.8L21 13v5.5A1.5 1.5 0 0 1 19.5 20h-15A1.5 1.5 0 0 1 3 18.5V13z"/>',
  journal: '<circle cx="12" cy="12" r="3.2"/><path d="M12 3v5.8M12 15.2V21"/>',
  tasks: '<path d="M10 6.5h10M10 12h10M10 17.5h10"/><path d="m3.5 6.5 1.5 1.5 2.5-3M3.5 12l1.5 1.5 2.5-3"/><circle cx="5.3" cy="17.5" r="1.3"/>',
  plugins: '<path d="M9 3v4M15 3v4"/><path d="M6 7h12v4a6 6 0 0 1-12 0z"/><path d="M12 17v4"/>',
  more: '<path d="M4 7h9M17 7h3M4 17h3M11 17h9"/><circle cx="15" cy="7" r="2"/><circle cx="9" cy="17" r="2"/>',
  send: '<path d="M7 17 17 7M8.5 7H17v8.5"/>',
  undo: '<path d="M9 14 4 9l5-5"/><path d="M4 9h10.5a5.5 5.5 0 0 1 0 11H11"/>',
  warn: '<path d="M10.3 4.2 2.6 17.5A2 2 0 0 0 4.3 20.5h15.4a2 2 0 0 0 1.7-3L13.7 4.2a2 2 0 0 0-3.4 0z"/><path d="M12 9.5v4M12 17h.01"/>',
  check: '<path d="m5 12.5 4.5 4.5L19 7.5"/>',
  x: '<path d="M6 6l12 12M18 6 6 18"/>',
  chev: '<path d="m9 6 6 6-6 6"/>',
  back: '<path d="m15 5-7 7 7 7"/>',
  bell: '<path d="M6 16v-5a6 6 0 0 1 12 0v5l1.5 2h-15z"/><path d="M10 20.5a2.2 2.2 0 0 0 4 0"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="m11 12 8.5-8.5M16.5 6.5l2.5 2.5M14 9l2 2"/>',
  alert: '<circle cx="12" cy="12" r="9"/><path d="M12 7.5v5M12 16h.01"/>',
  power: '<path d="M12 3v8"/><path d="M6.3 6.8a8 8 0 1 0 11.4 0"/>',
  shield: '<path d="M12 3 5 6v5c0 4.5 3 8 7 10 4-2 7-5.5 7-10V6z"/><path d="m9 12 2 2 4-4"/>',
  retry: '<path d="M20 11a8 8 0 1 0-2.3 5.7"/><path d="M20 5v6h-6"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  edit: '<path d="M4 20h4L19 9l-4-4L4 16z"/><path d="m13.5 6.5 4 4"/>',
  file: '<path d="M7 3h7l5 5v13H7z"/><path d="M14 3v5h5"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/>',
  search: '<circle cx="10.5" cy="10.5" r="6"/><path d="m15 15 5.5 5.5"/>',
  person: '<circle cx="12" cy="8.5" r="3.8"/><path d="M4.5 20.5a7.5 7.5 0 0 1 15 0"/>',
  agent: '<rect x="4" y="7" width="16" height="12" rx="3"/><path d="M12 7V4M9 12v1.5M15 12v1.5M2 13h2M20 13h2"/>',
  mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3.5 7.5 8.5 6 8.5-6"/>',
  calendar: '<rect x="3.5" y="5" width="17" height="15" rx="2"/><path d="M3.5 10h17M8 3v4M16 3v4"/>',
  note: '<path d="M6.5 3.5H15l4 4V19a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 5 19V5a1.5 1.5 0 0 1 1.5-1.5z"/><path d="M9 12h6M9 16h4"/>',
  folder: '<path d="M3 7.5A1.5 1.5 0 0 1 4.5 6H9l2 2.5h8.5A1.5 1.5 0 0 1 21 10v8a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 18z"/>',
  chat: '<path d="M4 5.5h16V16H10l-4.5 3.5V16H4z"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z"/>',
};

// Logo marks of the services in doorman/mcp/known.py: [the brand's colour, the mark's path on a 24px grid].
// From Simple Icons (CC0); the marks themselves belong to their owners (THIRD_PARTY.md).
const BRANDS = {
  notion: ["000000", "M4.459 4.208c.746.606 1.026.56 2.428.466l13.215-.793c.28 0 .047-.28-.046-.326L17.86 1.968c-.42-.326-.981-.7-2.055-.607L3.01 2.295c-.466.046-.56.28-.374.466zm.793 3.08v13.904c0 .747.373 1.027 1.214.98l14.523-.84c.841-.046.935-.56.935-1.167V6.354c0-.606-.233-.933-.748-.887l-15.177.887c-.56.047-.747.327-.747.933zm14.337.745c.093.42 0 .84-.42.888l-.7.14v10.264c-.608.327-1.168.514-1.635.514-.748 0-.935-.234-1.495-.933l-4.577-7.186v6.952L12.21 19s0 .84-1.168.84l-3.222.186c-.093-.186 0-.653.327-.746l.84-.233V9.854L7.822 9.76c-.094-.42.14-1.026.793-1.073l3.456-.233 4.764 7.279v-6.44l-1.215-.139c-.093-.514.28-.887.747-.933zM1.936 1.035l13.31-.98c1.634-.14 2.055-.047 3.082.7l4.249 2.986c.7.513.934.653.934 1.213v16.378c0 1.026-.373 1.634-1.68 1.726l-15.458.934c-.98.047-1.448-.093-1.962-.747l-3.129-4.06c-.56-.747-.793-1.306-.793-1.96V2.667c0-.839.374-1.54 1.447-1.632z"],
  linear: ["5E6AD2", "M2.886 4.18A11.982 11.982 0 0 1 11.99 0C18.624 0 24 5.376 24 12.009c0 3.64-1.62 6.903-4.18 9.105L2.887 4.18ZM1.817 5.626l16.556 16.556c-.524.33-1.075.62-1.65.866L.951 7.277c.247-.575.537-1.126.866-1.65ZM.322 9.163l14.515 14.515c-.71.172-1.443.282-2.195.322L0 11.358a12 12 0 0 1 .322-2.195Zm-.17 4.862 9.823 9.824a12.02 12.02 0 0 1-9.824-9.824Z"],
  github: ["181717", "M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"],
  gitlab: ["FC6D26", "m23.6004 9.5927-.0337-.0862L20.3.9814a.851.851 0 0 0-.3362-.405.8748.8748 0 0 0-.9997.0539.8748.8748 0 0 0-.29.4399l-2.2055 6.748H7.5375l-2.2057-6.748a.8573.8573 0 0 0-.29-.4412.8748.8748 0 0 0-.9997-.0537.8585.8585 0 0 0-.3362.4049L.4332 9.5015l-.0325.0862a6.0657 6.0657 0 0 0 2.0119 7.0105l.0113.0087.03.0213 4.976 3.7264 2.462 1.8633 1.4995 1.1321a1.0085 1.0085 0 0 0 1.2197 0l1.4995-1.1321 2.4619-1.8633 5.006-3.7489.0125-.01a6.0682 6.0682 0 0 0 2.0094-7.003z"],
  atlassian: ["0052CC", "M7.12 11.084a.683.683 0 00-1.16.126L.075 22.974a.703.703 0 00.63 1.018h8.19a.678.678 0 00.63-.39c1.767-3.65.696-9.203-2.406-12.52zM11.434.386a15.515 15.515 0 00-.906 15.317l3.95 7.9a.703.703 0 00.628.388h8.19a.703.703 0 00.63-1.017L12.63.38a.664.664 0 00-1.196.006z"],
  sentry: ["362D59", "M13.91 2.505c-.873-1.448-2.972-1.448-3.844 0L6.904 7.92a15.478 15.478 0 0 1 8.53 12.811h-2.221A13.301 13.301 0 0 0 5.784 9.814l-2.926 5.06a7.65 7.65 0 0 1 4.435 5.848H2.194a.365.365 0 0 1-.298-.534l1.413-2.402a5.16 5.16 0 0 0-1.614-.913L.296 19.275a2.182 2.182 0 0 0 .812 2.999 2.24 2.24 0 0 0 1.086.288h6.983a9.322 9.322 0 0 0-3.845-8.318l1.11-1.922a11.47 11.47 0 0 1 4.95 10.24h5.915a17.242 17.242 0 0 0-7.885-15.28l2.244-3.845a.37.37 0 0 1 .504-.13c.255.14 9.75 16.708 9.928 16.9a.365.365 0 0 1-.327.543h-2.287c.029.612.029 1.223 0 1.831h2.297a2.206 2.206 0 0 0 1.922-3.31z"],
  todoist: ["E44332", "M21 0H3C1.35 0 0 1.35 0 3v3.858s3.854 2.24 4.098 2.38c.31.18.694.177 1.004 0 .26-.147 8.02-4.608 8.136-4.675.279-.161.58-.107.748-.01.164.097.606.348.84.48.232.134.221.502.013.622l-9.712 5.59c-.346.2-.69.204-1.048.002C3.478 10.907.998 9.463 0 8.882v2.02l4.098 2.38c.31.18.694.177 1.004 0 .26-.147 8.02-4.609 8.136-4.676.279-.16.58-.106.748-.008.164.096.606.347.84.48.232.133.221.5.013.62-.208.121-9.288 5.346-9.712 5.59-.346.2-.69.205-1.048.002C3.478 14.951.998 13.506 0 12.926v2.02l4.098 2.38c.31.18.694.177 1.004 0 .26-.147 8.02-4.609 8.136-4.676.279-.16.58-.106.748-.009.164.097.606.348.84.48.232.133.221.502.013.622l-9.712 5.59c-.346.199-.69.204-1.048.001C3.478 18.994.998 17.55 0 16.97V21c0 1.65 1.35 3 3 3h18c1.65 0 3-1.35 3-3V3c0-1.65-1.35-3-3-3z"],
  airtable: ["18BFFF", "M11.992 1.966c-.434 0-.87.086-1.28.257L1.779 5.917c-.503.208-.49.908.012 1.116l8.982 3.558a3.266 3.266 0 0 0 2.454 0l8.982-3.558c.503-.196.503-.908.012-1.116l-8.957-3.694a3.255 3.255 0 0 0-1.272-.257zM23.4 8.056a.589.589 0 0 0-.222.045l-10.012 3.877a.612.612 0 0 0-.38.564v8.896a.6.6 0 0 0 .821.552L23.62 18.1a.583.583 0 0 0 .38-.551V8.653a.6.6 0 0 0-.6-.596zM.676 8.095a.644.644 0 0 0-.48.19C.086 8.396 0 8.53 0 8.69v8.355c0 .442.515.737.908.54l6.27-3.006.307-.147 2.969-1.436c.466-.22.43-.908-.061-1.092L.883 8.138a.57.57 0 0 0-.207-.044z"],
  clickup: ["7B68EE", "M2 18.439l3.69-2.828c1.961 2.56 4.044 3.739 6.363 3.739 2.307 0 4.33-1.166 6.203-3.704L22 18.405C19.298 22.065 15.941 24 12.053 24 8.178 24 4.788 22.078 2 18.439zM12.04 6.15l-6.568 5.66-3.036-3.52L12.055 0l9.543 8.296-3.05 3.509z"],
  intercom: ["6AFDEF", "M21 0H3C1.343 0 0 1.343 0 3v18c0 1.658 1.343 3 3 3h18c1.658 0 3-1.342 3-3V3c0-1.657-1.342-3-3-3zm-5.801 4.399c0-.44.36-.8.802-.8.44 0 .8.36.8.8v10.688c0 .442-.36.801-.8.801-.443 0-.802-.359-.802-.801V4.399zM11.2 3.994c0-.44.357-.799.8-.799s.8.359.8.799v11.602c0 .44-.357.8-.8.8s-.8-.36-.8-.8V3.994zm-4 .405c0-.44.359-.8.799-.8.443 0 .802.36.802.8v10.688c0 .442-.36.801-.802.801-.44 0-.799-.359-.799-.801V4.399zM3.199 6c0-.442.36-.8.802-.8.44 0 .799.358.799.8v7.195c0 .441-.359.8-.799.8-.443 0-.802-.36-.802-.8V6zM20.52 18.202c-.123.105-3.086 2.593-8.52 2.593-5.433 0-8.397-2.486-8.521-2.593-.335-.288-.375-.792-.086-1.128.285-.334.79-.375 1.125-.09.047.041 2.693 2.211 7.481 2.211 4.848 0 7.456-2.186 7.479-2.207.334-.289.839-.25 1.128.086.289.336.25.84-.086 1.128zm.281-5.007c0 .441-.36.8-.801.8-.441 0-.801-.36-.801-.8V6c0-.442.361-.8.801-.8.441 0 .801.357.801.8v7.195z"],
  stripe: ["635BFF", "M13.976 9.15c-2.172-.806-3.356-1.426-3.356-2.409 0-.831.683-1.305 1.901-1.305 2.227 0 4.515.858 6.09 1.631l.89-5.494C18.252.975 15.697 0 12.165 0 9.667 0 7.589.654 6.104 1.872 4.56 3.147 3.757 4.992 3.757 7.218c0 4.039 2.467 5.76 6.476 7.219 2.585.92 3.445 1.574 3.445 2.583 0 .98-.84 1.545-2.354 1.545-1.875 0-4.965-.921-6.99-2.109l-.9 5.555C5.175 22.99 8.385 24 11.714 24c2.641 0 4.843-.624 6.328-1.813 1.664-1.305 2.525-3.236 2.525-5.732 0-4.128-2.524-5.851-6.594-7.305h.003z"],
  huggingface: ["FFD21E", "M12.025 1.13c-5.77 0-10.449 4.647-10.449 10.378 0 1.112.178 2.181.503 3.185.064-.222.203-.444.416-.577a.96.96 0 0 1 .524-.15c.293 0 .584.124.84.284.278.173.48.408.71.694.226.282.458.611.684.951v-.014c.017-.324.106-.622.264-.874s.403-.487.762-.543c.3-.047.596.06.787.203s.31.313.4.467c.15.257.212.468.233.542.01.026.653 1.552 1.657 2.54.616.605 1.01 1.223 1.082 1.912.055.537-.096 1.059-.38 1.572.637.121 1.294.187 1.967.187.657 0 1.298-.063 1.921-.178-.287-.517-.44-1.041-.384-1.581.07-.69.465-1.307 1.081-1.913 1.004-.987 1.647-2.513 1.657-2.539.021-.074.083-.285.233-.542.09-.154.208-.323.4-.467a1.08 1.08 0 0 1 .787-.203c.359.056.604.29.762.543s.247.55.265.874v.015c.225-.34.457-.67.683-.952.23-.286.432-.52.71-.694.257-.16.547-.284.84-.285a.97.97 0 0 1 .524.151c.228.143.373.388.43.625l.006.04a10.3 10.3 0 0 0 .534-3.273c0-5.731-4.678-10.378-10.449-10.378M8.327 6.583a1.5 1.5 0 0 1 .713.174 1.487 1.487 0 0 1 .617 2.013c-.183.343-.762-.214-1.102-.094-.38.134-.532.914-.917.71a1.487 1.487 0 0 1 .69-2.803m7.486 0a1.487 1.487 0 0 1 .689 2.803c-.385.204-.536-.576-.916-.71-.34-.12-.92.437-1.103.094a1.487 1.487 0 0 1 .617-2.013 1.5 1.5 0 0 1 .713-.174m-10.68 1.55a.96.96 0 1 1 0 1.921.96.96 0 0 1 0-1.92m13.838 0a.96.96 0 1 1 0 1.92.96.96 0 0 1 0-1.92M8.489 11.458c.588.01 1.965 1.157 3.572 1.164 1.607-.007 2.984-1.155 3.572-1.164.196-.003.305.12.305.454 0 .886-.424 2.328-1.563 3.202-.22-.756-1.396-1.366-1.63-1.32q-.011.001-.02.006l-.044.026-.01.008-.03.024q-.018.017-.035.036l-.032.04a1 1 0 0 0-.058.09l-.014.025q-.049.088-.11.19a1 1 0 0 1-.083.116 1.2 1.2 0 0 1-.173.18q-.035.029-.075.058a1.3 1.3 0 0 1-.251-.243 1 1 0 0 1-.076-.107c-.124-.193-.177-.363-.337-.444-.034-.016-.104-.008-.2.022q-.094.03-.216.087-.06.028-.125.063l-.13.074q-.067.04-.136.086a3 3 0 0 0-.135.096 3 3 0 0 0-.26.219 2 2 0 0 0-.12.121 2 2 0 0 0-.106.128l-.002.002a2 2 0 0 0-.09.132l-.001.001a1.2 1.2 0 0 0-.105.212q-.013.036-.024.073c-1.139-.875-1.563-2.317-1.563-3.203 0-.334.109-.457.305-.454m.836 10.354c.824-1.19.766-2.082-.365-3.194-1.13-1.112-1.789-2.738-1.789-2.738s-.246-.945-.806-.858-.97 1.499.202 2.362c1.173.864-.233 1.45-.685.64-.45-.812-1.683-2.896-2.322-3.295s-1.089-.175-.938.647 2.822 2.813 2.562 3.244-1.176-.506-1.176-.506-2.866-2.567-3.49-1.898.473 1.23 2.037 2.16c1.564.932 1.686 1.178 1.464 1.53s-3.675-2.511-4-1.297c-.323 1.214 3.524 1.567 3.287 2.405-.238.839-2.71-1.587-3.216-.642-.506.946 3.49 2.056 3.522 2.064 1.29.33 4.568 1.028 5.713-.624m5.349 0c-.824-1.19-.766-2.082.365-3.194 1.13-1.112 1.789-2.738 1.789-2.738s.246-.945.806-.858.97 1.499-.202 2.362c-1.173.864.233 1.45.685.64.451-.812 1.683-2.896 2.322-3.295s1.089-.175.938.647-2.822 2.813-2.562 3.244 1.176-.506 1.176-.506 2.866-2.567 3.49-1.898-.473 1.23-2.037 2.16c-1.564.932-1.686 1.178-1.464 1.53s3.675-2.511 4-1.297c.323 1.214-3.524 1.567-3.287 2.405.238.839 2.71-1.587 3.216-.642.506.946-3.49 2.056-3.522 2.064-1.29.33-4.568 1.028-5.713-.624"],
};

const PLUGIN_GLYPHS = { notes: "note", nextcloud_notes: "note", files: "folder", mail_imap: "mail", mail_outlook: "mail",
  caldav: "calendar", google_calendar: "calendar", ics: "calendar", contacts: "person", whatsapp: "chat", teams: "chat" };

// A square tile in front of a name: a known service's logo on its colour, a plugin type's glyph, or the
// name's first letter. Images can't come from a server (img-src 'self'), so everything here ships with the app.
function tile({ brand = null, glyph = null, title = "" }) {
  const mark = BRANDS[brand];
  let inner;
  if (mark) {
    const [hex, d] = mark;
    const [r, g, b] = [0, 2, 4].map((i) => parseInt(hex.slice(i, i + 2), 16));
    const ink = 0.299 * r + 0.587 * g + 0.114 * b > 150 ? "#0f1115" : "#ffffff";  // whichever reads on the colour
    inner = `<rect class="tile-edge" width="36" height="36" rx="9" fill="#${hex}"/><path transform="translate(8 8) scale(0.8333)" fill="${ink}" d="${d}"/>`;
  } else if (ICONS[glyph]) {
    inner = `<rect class="tile-bg" width="36" height="36" rx="9"/><g class="tile-glyph" transform="translate(7 7) scale(0.9167)">${ICONS[glyph]}</g>`;
  } else {
    const letter = (String(title).match(/[A-Za-z0-9]/) || ["?"])[0].toUpperCase();
    inner = `<rect class="tile-bg" width="36" height="36" rx="9"/><text class="tile-letter" x="18" y="18.5" text-anchor="middle" dominant-baseline="central">${letter}</text>`;
  }
  const tpl = document.createElement("template");
  tpl.innerHTML = `<svg class="tile" viewBox="0 0 36 36" aria-hidden="true" focusable="false">${inner}</svg>`;
  return tpl.content.firstChild;
}

function icon(name, cls = "") {
  const tpl = document.createElement("template");
  tpl.innerHTML = `<svg class="icon ${cls}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">${ICONS[name]}</svg>`;
  return tpl.content.firstChild;
}

// A server's reason as a sentence: capitalised, with a full stop. Doorman's reasons are written lower-case
// for agents and logs.
function sentence(text) {
  const s = String(text || "").trim();
  if (!s) return "Something went wrong.";
  return `${s.charAt(0).toUpperCase()}${s.slice(1)}${/[.!?…]$/.test(s) ? "" : "."}`;
}

const OFFLINE_TEXT = "No connection to Doorman. Nothing was sent or changed.";

async function api(method, path, body) {
  const options = { method, headers: { "X-Requested-With": "doorman" }, credentials: "same-origin" };
  if (body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  let response;
  try {
    response = await fetch(path, options);
  } catch (err) {  // no answer at all: offline, or Doorman unreachable. The browser's own words never show.
    setOffline(true);
    throw Object.assign(new Error(OFFLINE_TEXT), { code: "offline" });
  }
  setOffline(false);
  const data = await response.json().catch(() => ({}));
  // signed_out, which no server error uses: callers stay quiet on it (the login screen says why), and a plugin's
  // sign-in errors (code "login": "start again", "Google says: …") still reach the owner
  if (response.status === 401) { toLogin(); throw Object.assign(new Error("Log in to carry on."), { code: "signed_out" }); }
  if (!response.ok) {
    const reason = data.reason || data.error;
    const text = reason ? sentence(reason) : response.status >= 500 ? "Doorman couldn't answer just now. Try again in a moment."
      : `Doorman refused this (HTTP ${response.status}).`;
    throw Object.assign(new Error(text), { code: data.code, reason });
  }
  return data;
}

// ---------------------------------------------------------------- session and connection

// An expired session sends the owner to the login screen; afterwards they land where they were, such as
// the approval a push opened, not on the inbox.
function toLogin() {
  const here = location.hash || "";
  if (here.startsWith("#/login")) return;
  try { sessionStorage.setItem("afterLogin", here); } catch (_) { /* private mode */ }
  location.hash = "#/login";
}

function afterLogin(take = true) {
  let to = null;
  try { to = sessionStorage.getItem("afterLogin"); if (take) sessionStorage.removeItem("afterLogin"); } catch (_) { /* private mode */ }
  return to && /^#\/[a-z]/.test(to) && !to.startsWith("#/login") ? to : null;
}

// Offline (or Doorman out of reach): a sticky red banner says so, and nothing that would send can be tapped.
let offline = false;
function setOffline(on) {
  on = on || navigator.onLine === false;
  if (on === offline) return;
  offline = on;
  document.getElementById("offline").hidden = !on;
  for (const b of document.querySelectorAll("[data-needs-net]")) b.disabled = on;
}

// One message at a time. A toast may carry one link (e.g. to the entry a send became); it then stays
// longer, so there is time to reach it. "info" is news that isn't a failure (already decided elsewhere).
function toast(text, kind = "", link = null, ms = null) {
  const el = h("div", { class: `toast ${kind}`, role: kind === "error" ? "alert" : "status" },
    icon(kind === "error" || kind === "info" ? "alert" : "check", "sm"), h("span", { class: "grow" }, text),
    link ? h("a", { class: "toast-link", href: link.href }, link.label) : null);
  toasts.replaceChildren(el);
  setTimeout(() => { el.classList.add("leaving"); setTimeout(() => el.remove(), 180); }, ms || (kind || link ? 6000 : 3500));
}

// Runs an action from a control: busy while it runs, errors as a toast. A cancelled sheet returns null.
// A lapsed session needs no toast: the login screen says why it's there.
async function act(control, fn, done) {
  const isButton = control.tagName === "BUTTON";
  control.disabled = true;
  if (isButton) control.setAttribute("aria-busy", "true");
  try { const out = await fn(); if (done) done(out); } catch (err) { if (err.code !== "signed_out") toast(err.message, "error"); }
  finally { control.disabled = offline && control.hasAttribute("data-needs-net"); control.removeAttribute("aria-busy"); }
}

// After the owner did something small, the toast names it: "Routine “Brief” deleted". With undo, the
// toast carries it as its one link-like action.
function undoToast(text, undo) {
  const button = h("button", { class: "toast-link", type: "button" }, "Undo");
  const el = h("div", { class: "toast", role: "status" }, icon("check", "sm"), h("span", { class: "grow" }, text), button);
  button.onclick = () => { el.remove(); undo().then(() => route()).catch((err) => toast(err.message, "error")); };
  toasts.replaceChildren(el);
  setTimeout(() => { el.classList.add("leaving"); setTimeout(() => el.remove(), 180); }, 6000);
}

// ---------------------------------------------------------------- motion

// Motion explains what just happened; it never decorates. With reduced motion, things fade instead of moving.
const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
const EASE_OUT = "cubic-bezier(0.16, 1, 0.3, 1)";   // arrivals
const EASE_IN = "cubic-bezier(0.4, 0, 1, 1)";       // exits: quicker, out of the way

function play(el, keyframes, options) {
  if (!el || !el.animate) return Promise.resolve();
  return el.animate(keyframes, { easing: EASE_OUT, ...options }).finished.catch(() => {});
}

// Something you just caused settles into place: a task you added, the empty inbox after the last send.
function arrive(el, dy = -6) {
  return play(el, reducedMotion.matches ? [{ opacity: 0 }, { opacity: 1 }]
    : [{ opacity: 0, transform: `translateY(${dy}px)` }, { opacity: 1, transform: "none" }], { duration: 340 });
}

// A decided card leaves the inbox: an approved send goes off along its arrow, a denied one sinks away.
// Then everything below it slides up into the gap (FLIP), and the screen is re-fetched once all is still.
const EXITS = {
  approved: { opacity: 0, transform: "translate(24px, -12px) scale(0.98)" },
  denied: { opacity: 0, transform: "translateY(12px) scale(0.97)" },
  done: { opacity: 0, transform: "scale(0.97)" },
};
let leaving = 0;
async function dismiss(card, how = "done") {
  if (!card || !card.isConnected) return route();
  leaving++;
  card.inert = true;
  const section = card.closest(".section");
  const lastInSection = section && section.querySelectorAll("article").length === 1;
  const gone = lastInSection ? section : card;
  const count = section && section.querySelector(".section-head .count");
  if (count && !lastInSection) count.textContent = String(Math.max(0, Number(count.textContent) - 1));
  if (badgeCount) setBadge(badgeCount - 1);

  const still = reducedMotion.matches;
  await Promise.all([
    play(card, [{ opacity: 1, transform: "none" }, still ? { opacity: 0 } : EXITS[how] || EXITS.done],
      { duration: still ? 150 : 220, easing: EASE_IN, fill: "forwards" }),
    lastInSection ? play(section.querySelector(".section-head"), [{ opacity: 1 }, { opacity: 0 }], { duration: 200, fill: "forwards" }) : null,
  ]);

  const movers = [];  // whatever follows the card, at every level up to the screen
  for (let el = gone; el && el !== view; el = el.parentElement)
    for (let next = el.nextElementSibling; next; next = next.nextElementSibling) movers.push(next);
  const before = movers.map((el) => el.getBoundingClientRect().top);
  gone.remove();
  if (!still) {
    await Promise.all(movers.map((el, i) => {
      const dy = before[i] - el.getBoundingClientRect().top;
      return dy ? play(el, [{ transform: `translateY(${dy}px)` }, { transform: "none" }], { duration: 440 }) : null;
    }));
  }
  if (--leaving) return;  // another card is still on its way out; the last one refreshes
  await route();
  const empty = view.querySelector(".empty");
  const next = view.querySelector("article.approval");
  if (empty) arrive(empty, 8);
  else if (next && gone === card) arrive(next, 12);
  // keyboard and screen-reader users continue at the next decision, not at the top of the page
  const target = view.querySelector("article.approval [tabindex='-1']") || view.querySelector("h1");
  if (target) target.focus({ preventScroll: true });
}

// A switch whose change goes to Doorman; it flips back if Doorman refuses.
function toggle(checked, label, onchange, opts = {}) {
  const box = h("input", { type: "checkbox", role: "switch", class: "switch", checked, "aria-label": opts.ariaLabel || null });
  box.addEventListener("change", () => {
    const want = box.checked;
    box.disabled = true;
    onchange(want).catch((err) => { box.checked = !want; toast(err.message, "error"); }).finally(() => { box.disabled = false; });
  });
  if (!label) return box;
  return h("label", { class: "toggle" }, h("span", { class: "grow" }, h("span", {}, label),
    opts.hint ? h("span", { class: "secondary-text" }, opts.hint) : null), box);
}

// One tool's position: Off · Ask me · Auto (a read: Off · On). Like a switch, a pick goes to Doorman at
// once and moves back if Doorman refuses or onPick returns false (a confirm sheet the owner cancelled).
// Arrow keys move between positions; Space or Enter picks one, so browsing never changes a setting.
function modeControl(options, current, onPick, label) {
  let value = current;
  const group = h("div", { class: "modes", role: "radiogroup", "aria-label": label });
  const buttons = options.map(([mode, text, hint]) => h("button",
    { type: "button", class: "mode", role: "radio", "data-mode": mode, title: hint, "aria-description": hint }, text));
  const show = (mode) => {
    value = mode;
    for (const b of buttons) {
      const on = b.dataset.mode === mode;
      b.classList.toggle("on", on);
      b.setAttribute("aria-checked", String(on));
      b.tabIndex = on ? 0 : -1;
    }
  };
  for (const b of buttons) b.addEventListener("click", async () => {
    const mode = b.dataset.mode, was = value;
    if (mode === was || group.classList.contains("busy")) return;
    show(mode);
    group.classList.add("busy");
    try { if (await onPick(mode, was) === false) show(was); }
    catch (err) { show(was); toast(err.message, "error"); }
    finally { group.classList.remove("busy"); }
  });
  group.addEventListener("keydown", (ev) => {
    const step = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[ev.key];
    if (!step) return;
    ev.preventDefault();
    const at = buttons.indexOf(document.activeElement);
    const next = buttons[(at + step + buttons.length) % buttons.length];
    for (const b of buttons) b.tabIndex = b === next ? 0 : -1;
    next.focus();
  });
  group.append(...buttons);
  show(current);
  return group;
}

function localSwitch(checked, label, hint, keep) {
  const box = h("input", { type: "checkbox", role: "switch", class: "switch", checked, "data-keep": keep });
  const row = h("label", { class: "toggle" }, h("span", { class: "grow" }, h("span", {}, label),
    hint ? h("span", { class: "secondary-text" }, hint) : null), box);
  return { box, row };
}

function when(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return d.toLocaleString(undefined, { weekday: "short", day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
}

function clock(iso) {
  return iso ? new Date(iso).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" }) : "";
}

function day(isoDay) {
  if (!isoDay) return "Undated";
  const d = new Date(`${isoDay}T12:00:00`);
  const today = new Date(); const yesterday = new Date(Date.now() - 864e5);
  if (d.toDateString() === today.toDateString()) return "Today";
  if (d.toDateString() === yesterday.toDateString()) return "Yesterday";
  return d.toLocaleDateString(undefined, { weekday: "long", day: "numeric", month: "long" });
}

const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
function relative(iso) {
  if (!iso) return "";
  const minutes = Math.round((new Date(iso) - Date.now()) / 60000);
  if (Math.abs(minutes) < 60) return rtf.format(minutes, "minute");
  const hours = Math.round(minutes / 60);
  if (Math.abs(hours) < 48) return rtf.format(hours, "hour");
  return rtf.format(Math.round(hours / 24), "day");
}

const STATUS = {
  done: ["Done", "ok"], applied: ["Applied", "ok"],
  waiting_approval: ["Waiting for you", ""], sending: ["Sending", ""], unknown: ["Outcome unknown", "warn"],
  // a journal entry: approved, about to go out; an unknown send Doorman still checks on its own
  approved: ["Sending", ""], checking: ["Outcome unknown: Doorman is checking", "warn"],
  claimed: ["In progress", ""], pending: ["Waiting for the agent", ""], proposed: ["Proposed", ""],
  // one word for the owner's no: Deny, shown as "You denied". "Refused" is Doorman's own no to the agent.
  failed: ["Failed", "danger"], denied: ["Refused by Doorman", "danger"], rejected: ["You denied", "quiet"], expired: ["Expired", "danger"],
  reverted: ["Reverted", "quiet"], cancelled: ["Cancelled", "quiet"], closed: ["Closed", "quiet"],
  superseded: ["Replaced by your edit", "quiet"], edited: ["Edited", "quiet"],
};

// An approval's own states: there "denied" is the owner's Deny, not Doorman's refusal.
const APPROVAL_STATUS = { approved: ["You approved", "ok"], denied: ["You denied", "quiet"], edited: ["Replaced by your edit", "quiet"],
  failed: ["Closed: the agent changed it", "danger"], expired: ["Expired, nothing went out", "quiet"] };

function statusLabel(status, words = STATUS) {
  const [text, kind] = words[status] || [(status || "").replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase()), ""];
  return h("span", { class: `status ${kind}` }, text);
}

const SENDS = ["irreversible", "payment"];

function sendTag(text = "Can't be undone") {
  return h("span", { class: "tag send" }, icon("send", "sm"), text);
}

function diffBlock(lines) {
  if (!lines || !lines.length) return null;
  return h("div", { class: "diff", role: "group", "aria-label": "Changes" }, lines.map((l) => {
    const kind = l.sign === "+" ? "add" : l.sign === "-" ? "del" : "ctx";
    return h("div", { class: kind },
      h("span", { class: "sign", "aria-label": kind === "add" ? "added" : kind === "del" ? "removed" : null },
        l.sign === " " ? "" : l.sign === "-" ? "−" : "+"),
      h("span", { class: "dkey" }, l.field), h("span", {}, l.value));
  }));
}

function warnRow(content, kind = "") {
  return h("div", { class: `warn-row ${kind}` }, icon(kind === "danger" ? "alert" : "warn", "sm"), h("div", {}, content));
}

// The title row carries the title and at most one action (Stop agents, a status); the line under it runs full width.
function head(title, sub, end) {
  return h("header", { class: "head" },
    h("div", { class: "title-row" }, h("h1", { tabindex: "-1" }, title), end ? h("div", { class: "end" }, end) : null),
    sub ? h("p", { class: "sub" }, sub) : null);
}

function section(title, children, opts = {}) {
  return h("section", { class: "section", "aria-label": title },
    h("div", { class: "section-head" }, h("h2", {}, title),
      opts.count !== undefined ? h("span", { class: "count" }, String(opts.count)) : null,
      opts.end ? h("span", { class: "end" }, opts.end) : null),
    opts.note ? h("p", { class: "section-note" }, opts.note) : null, children);
}

function topbar(title, backHref) {
  return h("div", { class: "topbar" },
    h("a", { class: "button icon-only", href: backHref, "aria-label": "Back" }, icon("back")),
    h("span", { class: "title" }, title));
}

function plural(n, one, many) { return `${n} ${n === 1 ? one : many}`; }

// ---------------------------------------------------------------- sheets (native dialog)

// Opens a bottom sheet (a dialog on wide screens). Resolves with the chosen action's value, or null
// when dismissed. `body` may be a function of `finish(value)`, for a sheet whose content gives the answer
// itself (a picker); `cls` names such a variant.
function sheet({ title, body, actions, cancel = "Cancel", cls = "" }) {
  return new Promise((resolve) => {
    const dialog = h("dialog", { class: `sheet ${cls}`.trim(), "aria-labelledby": "sheet-title" });
    let result = null;
    let closing = false;
    const close = () => {  // slide away first, then close for real
      if (closing) return;
      closing = true;
      const done = () => dialog.close();
      dialog.classList.add("closing");
      dialog.addEventListener("animationend", done, { once: true });
      setTimeout(done, 320);  // in case no animation runs
    };
    const buttons = (actions || []).map((a) => h("button", {
      class: a.kind || "", type: "button", onclick: () => { result = a.value; close(); },
    }, a.label));
    // Cancel comes first in reading order, so Enter, Space or a screen reader never meet the confirming
    // (often destructive) button before it. CSS puts the confirming one nearest the thumb on phones and on
    // the right on wide screens.
    const heading = h("h2", { id: "sheet-title", tabindex: "-1" }, title);
    if (typeof body === "function") body = body((value) => { result = value; close(); });
    dialog.append(h("div", { class: "grab", "aria-hidden": "true" }),
      h("div", { class: "inner" }, heading,
        body ? h("div", { class: "sheet-body" }, body) : null,
        h("div", { class: "actions" }, h("button", { type: "button", onclick: close }, cancel), ...buttons)));
    dialog.addEventListener("click", (ev) => { if (ev.target === dialog) close(); });  // tap on the scrim
    dialog.addEventListener("cancel", (ev) => { ev.preventDefault(); close(); });  // Escape / Android back
    dialog.addEventListener("close", () => { dialog.remove(); resolve(result); });
    document.body.append(dialog);
    dialog.showModal();
    // A field the sheet is for gets the focus. An optional one (Deny's note) doesn't on a touch screen,
    // where focus pops the keyboard over the button the owner came to tap. Otherwise the title has it.
    const first = dialog.querySelector("input:not([type=radio]):not([type=checkbox]), textarea, select");
    if (first && !(first.dataset.optional && window.matchMedia("(pointer: coarse)").matches)) first.focus();
    else heading.focus();
  });
}

async function confirmSheet(title, text, label, kind = "primary") {
  return (await sheet({ title, body: typeof text === "string" ? h("p", {}, text) : text,
    actions: [{ label, value: true, kind }] })) === true;
}

// ---------------------------------------------------------------- WebAuthn

const b64u = {
  toBuf(s) { s = s.replace(/-/g, "+").replace(/_/g, "/"); const bin = atob(s + "===".slice((s.length + 3) % 4));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer; },
  fromBuf(b) { return btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); },
};

function creationOptions(o) {
  if (window.PublicKeyCredential && PublicKeyCredential.parseCreationOptionsFromJSON) return PublicKeyCredential.parseCreationOptionsFromJSON(o);
  return { ...o, challenge: b64u.toBuf(o.challenge), user: { ...o.user, id: b64u.toBuf(o.user.id) },
    excludeCredentials: (o.excludeCredentials || []).map((c) => ({ ...c, id: b64u.toBuf(c.id) })) };
}

function requestOptions(o) {
  if (window.PublicKeyCredential && PublicKeyCredential.parseRequestOptionsFromJSON) return PublicKeyCredential.parseRequestOptionsFromJSON(o);
  return { ...o, challenge: b64u.toBuf(o.challenge), allowCredentials: (o.allowCredentials || []).map((c) => ({ ...c, id: b64u.toBuf(c.id) })) };
}

function credentialJSON(c) {
  if (c.toJSON) return c.toJSON();
  const r = c.response, out = { id: c.id, rawId: b64u.fromBuf(c.rawId), type: c.type, clientExtensionResults: c.getClientExtensionResults() };
  out.response = { clientDataJSON: b64u.fromBuf(r.clientDataJSON) };
  if (r.attestationObject) out.response.attestationObject = b64u.fromBuf(r.attestationObject);
  if (r.authenticatorData) {
    out.response.authenticatorData = b64u.fromBuf(r.authenticatorData);
    out.response.signature = b64u.fromBuf(r.signature);
    if (r.userHandle) out.response.userHandle = b64u.fromBuf(r.userHandle);
  }
  return out;
}

async function signWithPasskey(optionsPath) {
  const start = await api("POST", optionsPath);
  const credential = await navigator.credentials.get({ publicKey: requestOptions(start.options) });
  return { challenge_id: start.challenge_id, credential: credentialJSON(credential) };
}

// ---------------------------------------------------------------- screens

const screens = {};
let approvalPasskey = false; // from /owner/settings: sign approvals with the passkey, or just tap
let signIn = "passkey";      // or "password" (doorman-admin sign-in): what logging in and confirming a change take
// No HTTPS (and not localhost): the browser gives no passkeys and no notifications, and the network can read along.
const plainHttp = !window.isSecureContext;
const PLAIN_HTTP = "This address has no HTTPS: others on your network can read what you type and see here, and this device gets no notifications.";

screens.login = async () => {
  const status = await api("GET", "/owner/auth/status");
  if (status.logged_in) { location.hash = afterLogin() || "#/inbox"; return null; }
  const mark = h("img", { src: "icon.svg", alt: "" });
  // why the login screen is here, when a lapsed session brought the owner from somewhere else
  const back = afterLogin(false);
  const why = back ? h("p", { class: "why" }, /^#\/(approvals|review)\//.test(back)
    ? "Log in, and Doorman takes you straight back to the send you opened."
    : "Your session ended. Log in, and Doorman takes you back to where you were.") : null;
  const into = () => { pushSynced = false; location.hash = afterLogin() || "#/inbox"; };
  signIn = status.sign_in || "passkey";
  if (signIn === "password") {
    // a form with a (fixed) user name, so a password manager offers to keep and fill it
    const password = h("input", { id: "password", type: "password", autocomplete: "current-password", required: true });
    const button = h("button", { class: "primary big block", type: "submit" }, icon("key"), "Log in");
    const form = h("form", { class: "foot", onsubmit: (ev) => {
      ev.preventDefault();
      act(button, () => api("POST", "/owner/auth/login/password", { password: password.value }), into);
    } },
      h("input", { type: "text", name: "username", autocomplete: "username", value: "owner", hidden: true }),
      h("label", { class: "field" }, h("span", { class: "label" }, "Password"), password,
        plainHttp ? h("span", { class: "hint" }, PLAIN_HTTP) : null),
      h("div", { class: "mt-5" }, button));
    return h("div", { class: "login" },
      h("div", { class: "hero" }, mark, h("h1", {}, "Doorman"),
        h("p", {}, "Approvals, the journal and every switch for your agent live here."), why),
      form);
  }
  // The first passkey needs a setup code from the host. So can another one, when no passkey you have works
  // here: a new phone, or a new address (a passkey only works on the address it was made on).
  if (!status.has_passkey || location.hash === "#/login/setup-code") {
    const code = h("input", { id: "code", class: "mono", autocomplete: "one-time-code", autocapitalize: "off", spellcheck: "false",
      placeholder: "abcd-ef01-2345", required: true });
    const label = h("input", { id: "label", value: "My phone" });
    const button = h("button", { class: "primary big block" }, icon("key"), "Register passkey");
    button.onclick = () => act(button, async () => {
      if (!code.value.trim()) throw new Error("Enter the setup code first.");
      const start = await api("POST", "/owner/auth/register/options", { setup_code: code.value.trim() });
      const credential = await navigator.credentials.create({ publicKey: creationOptions(start.options) });
      await api("POST", "/owner/auth/register/verify", { challenge_id: start.challenge_id, credential: credentialJSON(credential), label: label.value });
    }, into);
    const toPasskey = status.has_passkey
      ? h("a", { class: "quiet-link", href: "#/login" }, "Back to logging in with a passkey") : null;
    return h("div", { class: "login" },
      h("div", { class: "hero" }, mark, h("h1", {}, status.has_passkey ? "Add a passkey" : "Set up your passkey"),
        h("p", {}, "On Doorman's host, run ", h("code", {}, "doorman-admin setup-code"),
          " and enter the code below. The passkey is how you log in; once you're in, approving is a tap."),
        status.has_passkey ? h("p", {}, "Your other devices get a notice that a passkey was added.") : null, why),
      h("div", { class: "foot" },
        h("label", { class: "field" }, h("span", { class: "label" }, "Setup code"), code),
        h("label", { class: "field" }, h("span", { class: "label" }, "Name for this passkey"), label,
          h("span", { class: "hint" }, "Shown under More, so you can tell your devices apart.")),
        h("div", { class: "mt-5" }, button), toPasskey));
  }
  const button = h("button", { class: "primary big block" }, icon("key"), "Log in with passkey");
  button.onclick = () => act(button, async () => {
    const signed = await signWithPasskey("/owner/auth/login/options");
    await api("POST", "/owner/auth/login/verify", signed);
  }, into);
  return h("div", { class: "login" },
    h("div", { class: "hero" }, mark, h("h1", {}, "Doorman"),
      h("p", {}, "Approvals, the journal and every switch for your agent live here."), why),
    h("div", { class: "foot" }, button,
      h("a", { class: "quiet-link", href: "#/login/setup-code" }, "New device or no passkey here? Use a setup code")));
};

// ------------------------------------------------ approvals

// Where an address came from, in a few words: the mail's subject when the read log knows it, else the
// plugin. Never the raw reference (for mail a long Message-ID).
const AGENT_WROTE = "The agent wrote this address itself: it isn't in your trust list, your task or anything it read.";
function sourceText(seen) {
  if (!seen) return AGENT_WROTE;
  const by = seen.from && seen.from !== seen.value ? ` from ${seen.from}` : "";
  if (seen.answered) return `A recipient of the mail being answered${seen.label ? `, “${seen.label}”` : ""}${by}.`;
  if (seen.label) return `Address from “${seen.label}”${seen.from && seen.from !== seen.value ? ` (${seen.from})` : ""}.`;
  if (seen.plugin) return `Address from something the agent read in ${seen.plugin}.`;
  return AGENT_WROTE;
}

// Each warning is a headline plus at most one line. Amber: worth a look before you approve.
const CHECK_TEXT = {
  clean_session: ["Check for private data", "The agent read outside content and your private data before writing this."],
  direct_limit: ["Asks you this time", null],
  reviewer: ["Second opinion", null],
};

function trustButton(d) {
  if (!["email", "phone", "iban", "chat", "url"].includes(d.kind)) return null;
  const b = h("button", { class: "quiet", type: "button" }, `Trust ${d.value} from now on`);
  b.onclick = () => act(b, () => sensitive("POST", "/owner/trust", { kind: d.kind, value: d.value, label: (d.first_seen || {}).label || "" }),
    () => { b.replaceWith(h("span", { class: "meta" }, "Trusted. Next time there's no warning.")); });
  return b;
}

// Why a recipient without a warning counts as yours: "in your contacts (Anna de Vries)", "you wrote to them
// before (3 Nov)", "trust list (work)". Quiet, under the warnings; there is nothing to decide about it.
function knownLines(e) {
  const known = (e.known_destinations || []).filter((d) => d.source);
  return known.length ? h("div", { class: "known-list" }, known.map((d) =>
    h("p", { class: "meta" }, h("span", { class: "warn-value" }, d.value), ` · ${d.source}`))) : null;
}

function approvalWarnings(e) {
  const failed = ((e.checks && e.checks.checks) || []).filter((c) => !c.ok && !((c.data || {}).untrusted || []).length);
  const rows = [
    // asked for before a honeytoken paused the agent's key: it may have been following someone else
    e.key_paused ? warnRow([h("strong", { class: "warn-title" }, "The agent that asked for this is paused"),
      h("span", { class: "warn-text" }, "One of its later calls carried a decoy (a honeytoken), so it may be following someone else's instructions. Deny this unless you asked for exactly this.")], "danger") : null,
    ...(e.untrusted_destinations || []).map((d) => warnRow([
      h("strong", { class: "warn-title" }, "New recipient: ", h("span", { class: "warn-value" }, d.value)),
      h("span", { class: "warn-text" }, sourceText({ ...(d.first_seen || {}), value: d.value })),
    ])),
    ...failed.map((c) => {
      const [title, text] = CHECK_TEXT[c.name] || [null, null];
      return warnRow(title ? [h("strong", { class: "warn-title" }, title), h("span", { class: "warn-text" }, text || c.detail)] : c.detail);
    }),
  ].filter(Boolean);
  return rows.length ? h("div", { class: "warns" }, rows) : null;
}

function decide(approval, approve, note = "") {
  if (!approve) return api("POST", `/owner/approvals/${approval.id}/decide`, note ? { approve: false, note } : { approve: false });
  if (!approvalPasskey) {
    // the hash ties the tap to exactly what this screen shows; a changed payload is refused
    return api("POST", `/owner/approvals/${approval.id}/decide`, { approve: true, payload_hash: approval.payload_hash });
  }
  return signWithPasskey(`/owner/approvals/${approval.id}/options`)
    .then((signed) => api("POST", `/owner/approvals/${approval.id}/decide`, { approve: true, ...signed }));
}

// An approval that can't be decided any more (decided on another device or from a push, expired, changed
// by the agent), in plain words. Anything else is a real failure and stays an error.
const DECIDED_ELSEWHERE = {
  approved: "Already approved, on another device or from a notification.",
  declined: "Already denied, on another device or from a notification. Nothing went out.",
  "replaced by an edited version": "You edited this, so a new version took its place. Decide on that one.",
  "closed: the payload changed": "The agent changed this after asking, so it was closed. Nothing went out.",
  expired: "This expired before anyone decided. Nothing went out.",
};
function staleText(err) {
  if (err.code === "decided") return DECIDED_ELSEWHERE[String(err.reason || "").replace(/^already decided:\s*/, "")] || "Already decided elsewhere.";
  if (err.code === "expired") return "This expired before you decided. Nothing went out.";
  if (err.code === "payload_changed") return "The agent changed this since you opened it. Nothing went out. Read it again.";
  if (err.code === "approval" || err.code === "not_found") return "This isn't waiting for you any more. Nothing went out from here.";
  return null;
}

// Decides, or says why it can't be decided any more. A stale card never keeps a live Send button: the
// screen is fetched again, which removes the card or shows how it ended.
async function decideOrExplain(approval, approve, note) {
  try {
    return await decide(approval, approve, note);
  } catch (err) {
    const stale = staleText(err);
    if (!stale) throw err;
    return { stale };
  }
}

function explainStale(out, approval) {
  toast(out.stale, "info");
  clearPushes(approval.id);
  route();
}

// The pushes for approvals that are no longer waiting leave the notification tray: after a decision here,
// and on every inbox render (for what was decided on another device, or expired). `keep` holds the ids
// still pending; without it, only the approval `id` is cleared. A push for several sends of a task (`ids`)
// goes as soon as one of them is decided: its count is wrong from then on, and the inbox lists the rest.
async function clearPushes(id, keep = null) {
  try {
    const registration = "serviceWorker" in navigator && await navigator.serviceWorker.getRegistration();
    if (!registration || !registration.getNotifications) return;
    for (const n of await registration.getNotifications()) {
      // only the asking pushes: a line the service worker left after Accept ("Approved, but not sent") stays
      const of = n.data && n.data.approval ? (n.data.approval.ids || [n.data.approval.id]) : null;
      if (!of || !of[0]) continue;
      if (keep ? of.some((x) => !keep.has(x)) : of.includes(id)) n.close();
    }
  } catch (_) { /* no notifications here: nothing to clear */ }
}

// A send the approve call left under way: a big upload, a slow server (the call waits about 3 s).
const UNDER_WAY = ["sending", "running"];
const underWay = (results) => results.filter((r) => UNDER_WAY.includes(r.status));

// What an approved send did, in the words Accept on a push uses: sent, not sent, or nobody knows.
// Returns how the card leaves: along the send arrow only when everything went out (or is still going).
function sendOutcome(out, { m, change, to }) {
  const results = out.results || [];
  const link = { href: "#/journal", label: "See it in the journal" };
  const done = results.filter((r) => r.status === "done").length;
  const unknown = results.filter((r) => r.status === "unknown").length;
  const going = underWay(results).length;
  const failed = results.filter((r) => !["done", "unknown", ...UNDER_WAY].includes(r.status));
  const why = failed.find((r) => r.error);
  const checks = unknown && results.every((r) => r.status !== "unknown" || r.checking);
  const maybe = m ? `It may or may not have run on ${m.server}. Check there before you try again.`
    : checks ? "It may or may not have gone out. Doorman checks over the next half hour and tells you; don't send it again meanwhile."
    : "It may or may not have gone out. Check your Sent folder before you try again.";
  if (going && !failed.length && !unknown) {  // followed for a while, and still under way
    toast(`${done ? `${done} of ${results.length} sent. ` : ""}Still sending. If it doesn't go out, Doorman sends you a notification.`, "info", link);
    return "approved";
  }
  if (done === results.length) {
    toast(m ? `Done. ${m.server} ran it.` : change ? "Done. You can undo it in the journal."
      : to ? `Sent to ${to}` : results.length > 1 ? `All ${results.length} sent` : "Sent", "", link);
    return "approved";
  }
  if (results.length === 1) toast(unknown ? maybe : `Not ${change || m ? "done" : "sent"}: ${why ? sentence(why.error) : "Doorman stopped it."} Nothing went out.`, "error", link);
  else toast([`${done} of ${results.length} went out.`, failed.length ? `${failed.length} not sent${why ? `: ${sentence(why.error)}` : "."}` : null,
    unknown ? `${unknown} may or may not have gone out.` : null, going ? `${going} still sending.` : null].filter(Boolean).join(" "), "error", link);
  return "done";
}

// Doorman holds GET /owner/approvals/<id>/results open until the approval's sends ended. Followed for up to
// 90 s in all; what is still under way then says so, and a failure later comes as a push (Needs attention).
async function followSends(approvalIds) {
  const deadline = Date.now() + 90000;
  const results = [];
  for (const id of approvalIds) {
    let out = null;
    for (;;) {
      const left = Math.round((deadline - Date.now()) / 1000);
      try { out = await api("GET", `/owner/approvals/${id}/results?wait=${Math.max(0, Math.min(25, left))}`); } catch (_) { break; }
      if (out.done || left <= 0) break;
    }
    if (out) results.push(...out.results);
  }
  return results;
}

// What the approve calls answered (one per approval). All ended: the toast says how, as before. Some still
// under way: "Sending…" stays until the outcome replaces it. Returns "sending" then, else sendOutcome's word.
function reportSends(outs, ctx) {
  const results = outs.flatMap((o) => o.results || []);
  if (!underWay(results).length) return sendOutcome({ results }, ctx);
  toast(results.length > 1 ? `Sending ${results.length}…` : "Sending…", "", null, 95000);
  followSends(outs.filter((o) => underWay(o.results || []).length).map((o) => o.approval_id)).then((later) => {
    const now = new Map(later.map((r) => [r.entry_id, r]));
    sendOutcome({ results: results.map((r) => now.get(r.entry_id) || r) }, ctx);
  });
  return "sending";
}

// Deny asks once, with room for a short word to the agent: it reads the note in its feed and in doorman status.
// Several approvals (a burst) are denied together with the one note.
async function denyWithNote(button, approvals, { m, change }, after) {
  const many = Array.isArray(approvals) ? approvals : [approvals];
  const note = h("textarea", { id: "deny-note", maxlength: "500", rows: "3", "data-optional": "1", placeholder: "e.g. Not this week. Ask me again on Monday." });
  const ok = await sheet({ title: many.length > 1 ? `Deny all ${many.length}?` : m ? `Deny this on ${m.server}?` : change ? "Deny this change?" : "Deny this send?",
    body: [h("p", {}, change && !m ? "Nothing changes. The agent learns you said no." : "Nothing goes out. The agent learns you said no."),
      h("label", { class: "field" }, h("span", { class: "label" }, "Note for the agent (optional)"), note)],
    actions: [{ label: many.length > 1 ? `Deny all ${many.length}` : "Deny", value: true, kind: "primary" }] });
  if (!ok) return;
  const said = note.value.trim();
  act(button, async () => {
    const outs = [];
    for (const a of many) outs.push(await decideOrExplain(a, false, said));
    return outs;
  }, (outs) => {
    for (const a of many) clearPushes(a.id);
    if (outs.length === 1 && outs[0].stale) return explainStale(outs[0], many[0]);
    const n = outs.filter((o) => !o.stale).length;
    button.textContent = "Denied";
    const what = many.length > 1 ? `Denied ${plural(n, "send", "sends")}.` : "Denied.";
    toast(said ? `${what} The agent gets your note.` : `${what} The agent learns you said no.`);
    after("denied");
  });
}

const RECIPIENT_KEYS = ["to", "recipient", "recipients", "chat", "phone", "iban", "attendees"];
// A send whose own fields name nobody (a post in a channel, a chat by its id, most MCP tools) says where it
// goes another way: its summary and every field of its own (approvalCard's entryBlock).
const namesRecipient = (e) => RECIPIENT_KEYS.some((k) => present((e.args || {})[k]));

// Who a send goes to: the "to" (or chat, number, account) of every entry, when they all agree.
function recipientsOf(e) {
  const a = e.args || {};
  for (const k of RECIPIENT_KEYS) {
    const v = a[k];
    if (Array.isArray(v) && v.length) return v.map(String);
    if (typeof v === "string" && v) return [v];
  }
  return (e.untrusted_destinations || []).map((d) => d.value);
}

function approvalRecipient(approval) {
  const lists = approval.entries.map((e) => recipientsOf(e).join(", "));
  return lists.length && lists.every((l) => l && l === lists[0]) ? lists[0] : null;
}

// A send of an MCP server's tool: the server stands where a recipient would, the tool is what goes out.
const mcpOf = (approval) => (approval.entries.length === 1 && approval.entries[0].mcp) || null;
const mcpAction = (m) => (m.title && m.title !== m.tool ? m.title : `Run ${m.tool}`);

function avatar(name) {
  const letter = String(name || "").replace(/^[^\p{L}\p{N}]+/u, "")[0] || "?";
  return h("span", { class: "avatar", "aria-hidden": "true" }, letter);
}

// The expiry is only worth a line when it's close.
function expirySoon(iso) {
  return iso && (new Date(iso) - Date.now()) / 3600e3 < 3 ? `Expires ${relative(iso)}` : null;
}

// Every entry can be undone: the owner set its tool to Ask me, nothing goes out.
const undoable = (approval) => approval.entries.every((e) => e.tier === "reversible");

function decisionButtons(approval, after) {
  const m = mcpOf(approval);
  const to = m ? null : approvalRecipient(approval);
  const n = approval.entries.length;
  const change = undoable(approval);
  const sendText = m ? mcpAction(m) : change ? (n > 1 ? `Approve all ${n}` : "Approve") : to ? `Send to ${to}` : n > 1 ? `Send all ${n}` : "Send";
  const approve = h("button", { class: "primary", type: "button", "data-needs-net": "1", disabled: offline },
    icon(approvalPasskey ? "key" : change ? "check" : "send"), h("span", { class: "label" }, sendText));
  if (approvalPasskey) approve.setAttribute("aria-label", `${sendText}, with your passkey`);
  else if (m) approve.setAttribute("aria-label", `${sendText} on ${m.server}`);
  const deny = h("button", { type: "button", "aria-label": m ? `Deny ${sendText} on ${m.server}` : to && !change ? `Deny the send to ${to}` : "Deny" }, "Deny");
  approve.onclick = () => act(approve, () => decideOrExplain(approval, true), (out) => {
    if (out.stale) return explainStale(out, approval);
    clearPushes(approval.id);
    const how = reportSends([out], { m, change, to });
    approve.replaceChildren(icon(how === "done" ? "alert" : "check"), h("span", { class: "label" },
      how === "sending" ? (change || m ? "Running…" : "Sending…") : how === "approved" ? (change || m ? "Done" : "Sent") : "Not sent"));
    after(how === "sending" ? "approved" : how);
  });
  deny.onclick = () => denyWithNote(deny, approval, { m, change }, after);
  // a long address never gets cut off on the button that sends to it: Deny above, Send full width below
  return h("div", { class: `actions split${sendText.length > 22 ? " stacked" : ""}` }, deny, approve);
}

const TEXT_KEYS = ["body", "text", "message"];
const HEAD_KEYS = [["to", "To"], ["cc", "Cc"], ["bcc", "Bcc"], ["subject", "Subject"]];
// Plain names for the fields a send carries; any other key is shown with its first letter capitalised.
const FIELD_LABELS = { to: "To", cc: "Cc", bcc: "Bcc", subject: "Subject", body: "Message", text: "Message", message: "Message",
  id: "Item", path: "File", url: "Link", title: "Title", start: "Starts", end: "Ends", attendees: "Guests", location: "Place",
  amount: "Amount", iban: "Account", name: "Name", chat: "Chat", phone: "Phone", calendar: "Calendar", tags: "Tags" };
const fieldLabel = (k) => FIELD_LABELS[k] || (k.charAt(0).toUpperCase() + k.slice(1)).replace(/_/g, " ");
const present = (v) => v !== undefined && v !== null && v !== "" && !(Array.isArray(v) && !v.length);
const valueText = (v) => (typeof v === "string" ? v : Array.isArray(v) && v.every((x) => typeof x === "string") ? v.join(", ")
  : JSON.stringify(v, null, 2));
// What the message view shows in a way of its own (besides the text): every other field is listed with
// `rest`, for a send whose fields name no recipient, so where it goes is on screen.
const MESSAGE_KEYS = new Set(["to", "cc", "bcc", "subject", "attachments", "in_reply_to", "reply_to", "draft_id"]);

// A send as what it is: a message with its recipients, subject, text and attachments. Anything without a
// text (a calendar invitation, a payment) falls back to the plain field list. `rest`: the other fields too
// (a channel, a chat id), first, as they say where the message goes.
function messageView(args, opts = {}) {
  const a = args || {};
  const textKey = TEXT_KEYS.find((k) => typeof a[k] === "string");
  if (!textKey) return payloadList(a, opts);
  const others = opts.rest ? Object.keys(a).filter((k) => k !== textKey && !MESSAGE_KEYS.has(k) && present(a[k]))
    .map((k) => [k, fieldLabel(k)]) : [];
  const heads = [...others, ...HEAD_KEYS.filter(([k]) => !(opts.hideTo && k === "to") && present(a[k]))];
  return h("div", { class: "mail-view" },
    heads.length ? h("dl", { class: "mail-head" }, heads.map(([k, label]) => h("div", {}, h("dt", {}, label),
      h("dd", { class: k === "subject" ? "subject" : "" }, valueText(a[k]))))) : null,
    h("div", { class: "mail-body" }, a[textKey] || h("span", { class: "muted" }, "(no text)")),
    (a.attachments || []).length ? h("div", { class: "mail-files" }, a.attachments.map((f) => h("span", { class: "tag" }, icon("file", "sm"), String(f).split("/").pop()))) : null,
    a.in_reply_to || a.reply_to ? h("p", { class: "meta mail-note" }, "A reply in an existing thread.") : null,
    a.draft_id ? h("p", { class: "meta mail-note" }, "Your draft is deleted once it's sent.") : null);
}

function payloadList(args, opts = {}) {
  const skip = new Set([...(opts.hideTo ? ["to"] : []), ...(opts.skip || [])]);
  const keys = Object.keys(args || {}).filter((k) => !skip.has(k) && present(args[k]));
  if (!keys.length) return null;
  return h("dl", { class: "payload" }, keys.map((k) => h("div", {}, h("dt", {}, fieldLabel(k)),
    h("dd", { class: typeof args[k] === "string" ? "" : "mono" }, valueText(args[k])))));
}

// What leaves with a send, as the owner knows it: the note or file it points at (the plugin says what that
// is), plus any words of its own. Without that, the message view or the field list.
function whatGoesOut(e, opts = {}) {
  const a = e.args || {};
  const o = e.outgoing;
  if (!o) return messageView(a, opts);
  const own = TEXT_KEYS.find((k) => typeof a[k] === "string" && a[k].trim());
  return [h("div", { class: "goes-out" }, o.label ? h("div", { class: "label" }, o.label) : null,
      o.title ? h("div", { class: "title" }, o.title) : null, o.text ? h("div", { class: "text" }, o.text) : null),
    own ? h("div", { class: "goes-out" }, h("div", { class: "label" }, "Your message with it"), h("div", { class: "text" }, a[own])) : null,
    opts.rest ? payloadList(a, { skip: [own] }) : null];
}

// Who wrote a task, when it wasn't the owner: a trigger fills its text in from a stranger's mail, a reminder
// is the agent's own. A routine is the owner's text, like a task written in the app.
function strangerTask(origin, trusted) {
  if (trusted === null || trusted === undefined || trusted) return null;  // 1/true, or no task at all
  const o = String(origin || "");
  if (o.startsWith("trigger:")) return `trigger “${o.slice(8)}”`;
  if (o === "agent") return "a reminder the agent set";
  return o || "unknown";
}

// The task an approval belongs to, so the send can be judged against what was asked. Text the owner didn't
// write never reads like their instruction: it says so first. Two lines on a card, in full on the screen.
function taskHead(e) {
  const other = strangerTask(e.task_origin, e.task_trusted);
  return other ? `Not written by you: ${other}` : `For task ${e.task_id}`;
}

function taskLine(e, full = false) {
  return e.task_text ? h("p", { class: `task-line${full ? "" : " clamp"}` }, h("b", {}, taskHead(e)), ` · ${e.task_text}`)
    : h("p", { class: "task-line" }, h("b", {}, "Not part of a task"), " · the agent asked on its own");
}

const fill = (el, content) => el.replaceChildren(...[content].flat(3).filter(Boolean));

// "Always allow": from now on this tool of an MCP server runs without asking, while every check passes.
// Offered on a single send, after the decision in reading order, like "Trust <address>".
function alwaysRow(approval, after) {
  const m = mcpOf(approval);
  if (!m || !m.can_allow || m.allowed) return null;
  const plugin = approval.entries[0].plugin;
  const b = h("button", { class: "quiet", type: "button" }, `Always allow “${m.title}”`);
  b.onclick = async () => {
    const ok = await confirmSheet(`Always allow “${m.title}” on ${m.server}?`,
      h("div", {}, h("p", {}, "This one runs now. From now on the agent's calls to it run without asking you, as long as every check passes: a new recipient or a full daily limit still asks."),
        h("p", { class: "meta mt-2" }, `Each call is in the journal. None can be undone. Take it back on the ${m.server} card under Plugins.`)),
      "Allow and run");
    if (!ok) return;
    act(b, async () => {
      await sensitive("POST", `/owner/mcp/${plugin}/tools/${encodeURIComponent(m.tool)}`, { allowed: true });
      return decideOrExplain(approval, true);
    }, (out) => {
      if (out.stale) return explainStale(out, approval);
      clearPushes(approval.id);
      const how = reportSends([out], { m });
      if (how === "approved") toast(`Allowed. “${m.title}” ran, and runs without asking you from now on.`, "", { href: "#/plugins", label: "See it under Plugins" });
      after(how === "sending" ? "approved" : how);
    });
  };
  return h("div", { class: "trust-row" }, b);
}

function trustRow(approval) {
  const seen = new Set();
  const buttons = approval.entries.flatMap((e) => e.untrusted_destinations || [])
    .filter((d) => !seen.has(d.value) && seen.add(d.value)).map(trustButton).filter(Boolean);
  return buttons.length ? h("div", { class: "trust-row" }, buttons) : null;
}

// One decision: who gets what, which task asked for it, and Deny | Send to <recipient>. The inbox shows the
// oldest waiting send this way and queues the rest below it.
function approvalCard(approval, opts = {}) {
  const n = approval.entries.length;
  const payment = approval.entries.some((e) => e.tier === "payment");
  const pending = approval.status === undefined || approval.status === "pending";
  const m = mcpOf(approval);
  const to = m ? null : approvalRecipient(approval);
  let card = null;
  const after = (how) => (opts.after ? opts.after(how) : dismiss(card, how));
  const decision = pending && !opts.noDecision ? h("div", {},
    decisionButtons(approval, after),
    h("p", { class: "final" }, icon(undoable(approval) ? "undo" : "send", "sm"), finalLine(approval))) : null;
  const editing = (on) => { if (decision) decision.hidden = on; if (opts.onEditing) opts.onEditing(on); };
  const entryBlock = (e) => {
    // a send whose fields name nobody (a channel post, a chat by its id) still says where it goes: its
    // summary, where the plugin names the channel or chat, and every field besides the text
    const where = !undoable(approval) && !namesRecipient(e);
    const goesOut = (x) => whatGoesOut(x, { hideTo: !!to, rest: where });
    const body = h("div", {}, goesOut(e));
    const canEdit = pending && (e.editable || []).length;
    const edit = canEdit ? h("button", { class: "quiet", type: "button" }, icon("edit", "sm"), "Edit message") : null;
    const bar = edit ? h("div", { class: "edit-bar" }, edit) : null;
    if (edit) edit.onclick = () => {
      bar.hidden = true;
      editing(true);  // never approve the old text while the new one is half typed
      fill(body, [e.outgoing ? whatGoesOut({ ...e, args: {} }) : null, editForm(approval, e,
        () => { bar.hidden = false; editing(false); fill(body, goesOut(e)); },
        opts.onSaved || (() => { toast("Saved. Read it once more, then send."); route(); }))]);
      body.querySelector("textarea, input").focus();
    };
    // an undoable change says what it changes; a send shows what goes out, its recipient is the heading
    const plain = undoable(approval) || (!e.outgoing && !TEXT_KEYS.some((k) => typeof (e.args || {})[k] === "string"));
    return h("div", { class: "what" },
      n > 1 || plain || where ? h("p", { class: "summary" }, n === 1 && e.mcp ? e.mcp.title : e.summary) : null,
      e.edited_from ? h("span", { class: "tag" }, "Edited by you") : null,
      approvalWarnings(e), knownLines(e), body, opts.noTask ? null : taskLine(e, !!opts.fullTask), bar);
  };
  const lead = m ? "Run on" : payment ? "Pay" : undoable(approval) ? "Change for" : "Send to";
  const who = m ? m.server : to;
  const soon = pending ? expirySoon(approval.expires) : null;
  card = h("article", { class: "approval", "aria-label": who ? `${lead} ${who}` : undoable(approval) ? plural(n, "change", "changes") : plural(n, "send", "sends") },
    h("div", { class: "who" }, avatar(who || (undoable(approval) ? approval.entries[0].plugin : null) || "?"), h("div", { class: "grow" },
      h(opts.heading || "h2", { tabindex: "-1" }, h("span", { class: "lead" }, who ? lead : "Waiting for you"), " ",
        who || (undoable(approval) ? plural(n, "change", "changes") : plural(n, "send", "sends")))),
      soon ? h("span", { class: "meta" }, soon) : !pending ? statusLabel(approval.status, APPROVAL_STATUS) : null),
    approval.entries.map(entryBlock), decision,
    pending && !opts.noTrust ? [trustRow(approval), alwaysRow(approval, after)] : null,
    opts.askAgain ? askAgainRow(approval) : null);
  return card;
}

// An expired send went nowhere. If the owner still wants it, the agent hears so (approval_ask_again) and asks
// again: a new approval, with every check run afresh. Nothing is sent from the old one.
function askAgainRow(approval) {
  if (approval.status !== "expired") return null;
  if (approval.asked_again) {
    return h("p", { class: "ask-again meta" }, icon("check", "sm"), `You asked the agent again ${relative(approval.asked_again)}. Its new request shows up in the inbox.`);
  }
  const b = h("button", { type: "button", "data-needs-net": "1", disabled: offline }, icon("retry", "sm"), "Ask the agent again");
  b.onclick = () => act(b, () => api("POST", `/owner/approvals/${approval.id}/ask-again`),
    () => { toast("Asked. The agent sends you a new request to approve."); route(); });
  return h("div", { class: "ask-again" }, h("p", { class: "meta" }, "Still want it? The agent asks you again, with a new approval and every check run afresh."), b);
}

function finalLine(approval) {
  if (approval.entries.some((e) => e.tier === "payment")) return "Pays right away. Can't be undone.";
  if (undoable(approval)) return "Runs right away. You can undo it in the journal.";
  return mcpOf(approval) ? "Runs right away. Can't be undone." : "Sends right away. Can't be undone.";
}

// Change the text of a waiting send in place. Saving makes a new version (a new approval) to send;
// recipients aren't editable here.
function editForm(approval, entry, onCancel, onSaved) {
  const fields = {};
  const rows = entry.editable.map((key) => {
    const long = key !== "subject";
    const value = entry.args[key] === undefined || entry.args[key] === null ? "" : String(entry.args[key]);
    fields[key] = h(long ? "textarea" : "input", { id: `edit-${entry.id}-${key}`, class: long ? "edit-long" : null, value: long ? null : value });
    if (long) {
      fields[key].value = value;
      fields[key].rows = Math.min(24, Math.max(6, value.split("\n").length + 2));
    }
    const label = entry.outgoing && TEXT_KEYS.includes(key) ? "Your message with it (optional)"
      : TEXT_KEYS.includes(key) ? "Message" : fieldLabel(key);
    return h("label", { class: "field" }, h("span", { class: "label" }, label), fields[key]);
  });
  const save = h("button", { class: "primary", type: "button" }, "Save changes");
  const cancel = h("button", { type: "button" }, "Cancel");
  cancel.onclick = onCancel;
  save.onclick = () => act(save, () => {
    const changes = {};
    for (const [key, el] of Object.entries(fields)) if (el.value !== String(entry.args[key] ?? "")) changes[key] = el.value;
    if (!Object.keys(changes).length) throw new Error("Nothing changed yet.");
    return api("POST", `/owner/approvals/${approval.id}/edit`, { entry_id: entry.id, changes, payload_hash: approval.payload_hash })
      .catch((err) => { const stale = staleText(err); if (!stale) throw err; return { stale: `${stale} Your edit wasn't saved.` }; });
  }, (out) => (out.stale ? explainStale(out, approval) : onSaved(out)));
  return h("div", { class: "edit-form" }, rows,
    h("p", { class: "meta mt-2" }, "Recipients can't be changed here. To send it to someone else, deny it and tell the agent."),
    h("div", { class: "actions mt-3 to-end" }, cancel, save));
}

screens.approvals = async (id) => {
  const approval = await api("GET", `/owner/approvals/${id}`);
  const pending = approval.status === "pending";
  const leave = () => { location.hash = "#/inbox"; };
  const bar = pending ? h("div", { class: "decision-bar" },
    h("p", { class: "note" }, icon(undoable(approval) ? "undo" : "send", "sm"), finalLine(approval)),
    decisionButtons(approval, leave), trustRow(approval), alwaysRow(approval, leave)) : null;
  const card = approvalCard(approval, { noDecision: true, noTrust: true, heading: "h1", fullTask: true, askAgain: true,
    onEditing: (on) => { if (bar) bar.hidden = on; },
    onSaved: (out) => { toast("Saved. Read it once more, then send."); location.hash = `#/approvals/${out.approval_id}`; } });
  return [topbar(pending ? "Waiting for you" : "Approval", "#/inbox"), card, bar];
};

// ------------------------------------------------ review: several sends, one decision

const reviewHref = (approvals) => `#/review/${approvals.map((a) => a.id).join(",")}`;

// Approve all goes through each approval as a tap on its own screen would: its own payload hash (or passkey
// signature), its own checks on the server. One that changed or was decided elsewhere is skipped and named;
// the others still go.
async function approveAll(pending) {
  const outs = [], stale = [];
  for (const a of pending) {
    const out = await decideOrExplain(a, true);
    if (out.stale) stale.push(out.stale); else outs.push(out);
  }
  return { outs, results: outs.flatMap((o) => o.results || []), stale };
}

// Several sends at once (one task's burst, from its grouped push, the inbox or the task screen): each in
// full, warnings on its own card, then one decision at the end, below the last of them.
screens.review = async (ids) => {
  const wanted = [...new Set(String(ids || "").split(",").map(Number).filter((n) => Number.isInteger(n) && n > 0))].slice(0, 50);
  const found = (await Promise.all(wanted.map((id) => api("GET", `/owner/approvals/${id}`).catch((err) => {
    if (err.code === "signed_out") throw err;
    return null;
  })))).filter(Boolean);
  const pending = found.filter((a) => a.status === "pending");
  const entries = pending.flatMap((a) => a.entries);
  const tasks = [...new Set(entries.map((e) => e.task_id))];
  const oneTask = tasks.length === 1 && tasks[0] ? entries[0] : null;
  const change = pending.length && pending.every(undoable);
  const n = entries.length;
  const word = change ? plural(n, "change", "changes") : plural(n, "send", "sends");
  const title = !pending.length ? "Nothing left to decide" : oneTask ? `${word} from task ${oneTask.task_id}` : `${word} waiting`;
  const sub = !pending.length ? (found.length ? "Each one below was decided or expired already." : "These aren't waiting for you any more.")
    : "Read each one. The button at the end decides them all.";
  const replace = (oldId, newId) => { location.hash = `#/review/${wanted.map((id) => (id === oldId ? newId : id)).join(",")}`; };
  const end = h("div", { class: "review-end" });  // the one decision, below the last send
  const cards = found.map((a) => {
    const card = approvalCard(a, { noDecision: true, noTrust: true, noTask: !!oneTask, askAgain: true, heading: "h2",
      onEditing: (on) => { end.hidden = on; },
      onSaved: (out) => { toast("Saved. Read it once more, then decide."); replace(a.id, out.approval_id); } });
    if (a.status === "pending") {
      const leave = h("button", { class: "quiet", type: "button", "aria-label": `Deny only this one: ${a.entries[0].summary}` }, "Deny only this one");
      leave.onclick = () => denyWithNote(leave, a, { m: mcpOf(a), change: undoable(a) }, () => route());
      card.append(h("div", { class: "actions to-end" }, leave), trustRow(a) || "");
    }
    return card;
  });
  if (pending.length) {
    const warned = pending.filter((a) => a.entries.some((e) => approvalWarnings(e))).length;
    const to = pending.every((a) => !mcpOf(a)) ? (() => {
      const lists = pending.map(approvalRecipient);
      return lists.every((l) => l && l === lists[0]) ? lists[0] : null;
    })() : null;
    const label = change ? `Approve all ${n}` : to ? `Send all ${n} to ${to}` : `Send all ${n}`;
    const approve = h("button", { class: "primary", type: "button", "data-needs-net": "1", disabled: offline },
      icon(approvalPasskey ? "key" : change ? "check" : "send"), h("span", { class: "label" }, label));
    if (approvalPasskey) approve.setAttribute("aria-label", `${label}, with your passkey for each`);
    const deny = h("button", { type: "button" }, pending.length > 1 ? `Deny all ${pending.length}` : "Deny");
    deny.onclick = () => denyWithNote(deny, pending, { change }, () => { location.hash = "#/inbox"; });
    approve.onclick = () => act(approve, () => approveAll(pending), (out) => {
      for (const a of pending) clearPushes(a.id);
      if (!out.stale.length) {
        if (reportSends(out.outs, { change }) !== "done") location.hash = "#/inbox"; else route();
        return;
      }
      // some were decided elsewhere or changed: say what went and why the rest didn't, in one toast
      const done = out.results.filter((r) => r.status === "done").length;
      const going = underWay(out.results).length;
      const skipped = `${out.stale.length === 1 ? "One" : out.stale.length} wasn't decided here: ${out.stale[0]}`;
      toast(`${out.results.length ? `${done} of ${out.results.length} ${change ? "done" : "sent"}${going ? `, ${going} still going` : ""}. ` : ""}${skipped}`,
        done + going === out.results.length ? "info" : "error", { href: "#/journal", label: "See it in the journal" });
      route();
    });
    end.append(
      warned ? warnRow(`${warned === pending.length ? (pending.length === 1 ? "It has" : "Each has") : `${warned} of ${pending.length} ${warned === 1 ? "has" : "have"}`} a warning above. Read ${warned === 1 ? "it" : "them"} before you decide.`) : "",
      h("p", { class: "note" }, icon(change ? "undo" : "send", "sm"),
        change ? "Each runs right away. You can undo them in the journal." : approvalPasskey ? "Each goes out right away and can't be undone. Your passkey confirms each one." : "Each goes out right away. None can be undone."),
      h("div", { class: `actions split${label.length > 22 ? " stacked" : ""}` }, deny, approve));
  } else {
    end.append(h("a", { class: "button", href: "#/inbox" }, "Back to the inbox"));
  }
  return [topbar("Review", "#/inbox"), head(title, sub),
    oneTask ? h("div", { class: "surface pad-4 review-task" }, taskLine(oneTask, true)) : null,
    cards, end];
};

// ------------------------------------------------ changesets

// What happens to each item on Apply. A send carries the same marker as on a decision card.
function csHead(p) {
  const how = p.decision === "run" ? h("span", { class: "tag undo" }, icon("undo", "sm"), "Can be undone")
    : p.tier === "reversible" ? [h("span", { class: "tag undo" }, icon("undo", "sm"), "Can be undone"),
      h("span", { class: "meta" }, "Asks you once more before it runs")]
    : [sendTag(), h("span", { class: "meta" }, p.decision === "direct" ? "Goes out when you apply" : "Asks you once more before it goes out")];
  return [h("div", { class: "line1" }, h("span", {}, p.summary)), h("div", { class: "line2" }, how)];
}

async function rejectChangeset(button, cs) {
  const comment = h("textarea", { id: "reject-comment", "data-optional": "1", placeholder: "e.g. Keep the old tags" });
  const ok = await sheet({ title: "Deny this changeset?",
    body: [h("p", {}, "Nothing in it runs. The agent learns you said no, and sees your note."),
      h("label", { class: "field" }, h("span", { class: "label" }, "Note for the agent (optional)"), comment)],
    actions: [{ label: "Deny changeset", value: true, kind: "primary" }] });
  if (!ok) return;
  act(button, () => api("POST", `/owner/changesets/${cs.id}/reject`, { comment: comment.value.trim() }),
    () => { clearQuestionPushes((id) => id === cs.id, "changesets"); toast("Denied. Nothing in it ran."); location.hash = "#/inbox"; route(); });
}

// What Apply did, in counts: the status alone ("partially applied") doesn't say what was left out.
function appliedToast(out, all) {
  const results = out.results || [];
  const ran = results.filter((r) => !["conflict", "denied", "failed"].includes(r.status)).length;
  const asked = results.filter((r) => r.status === "waiting_approval").length;
  const link = { href: "#/journal", label: "See it in the journal" };
  const waits = asked ? ` ${plural(asked, "send waits", "sends wait")} for you in the inbox.` : "";
  if (ran === results.length) {
    toast(`Applied ${results.length === all ? (all === 1 ? "the change" : `all ${all}`) : `the ${results.length} you picked`}.${waits}`, "", link);
  } else {
    const changed = results.filter((r) => r.status === "conflict").length;
    toast(`Applied ${ran} of ${results.length}.${changed ? ` ${plural(changed, "item", "items")} changed since the agent looked.` : ""} The rest didn't run; see the journal.${waits}`, "error", link);
  }
}

function changesetCard(cs) {
  let card = null;
  const apply = h("button", { class: "primary", type: "button", "data-needs-net": "1", disabled: offline }, h("span", { class: "label" }, "Apply all"));
  apply.onclick = () => act(apply, () => api("POST", `/owner/changesets/${cs.id}/apply`, {}),
    (out) => { clearQuestionPushes((id) => id === cs.id, "changesets"); appliedToast(out, cs.preview.length); out.status === "proposed" ? route() : dismiss(card, "approved"); });
  const reject = h("button", { type: "button", "aria-label": `Deny: ${cs.title}` }, "Deny");
  reject.onclick = () => rejectChangeset(reject, cs);
  const sends = cs.preview.filter((p) => p.decision !== "run" && p.tier !== "reversible").length;
  card = h("article", { class: "approval", "aria-label": `Changeset: ${cs.title}` },
    h("div", { class: "who" }, h("div", { class: "grow" },
      h("h3", { tabindex: "-1" }, cs.title))),
    h("p", { class: "task-line" }, `${plural(cs.preview.length, "change", "changes")} proposed by the agent. Nothing runs until you apply it.`),
    h("div", { class: "cs-list" }, cs.preview.map((p) => h("div", { class: "cs-item" },
      h("div", { class: "grow" }, csHead(p),
        (p.warnings || []).length ? h("div", { class: "warns" }, p.warnings.map((w) => warnRow(w))) : null)))),
    h("a", { class: "more-link", href: `#/changesets/${cs.id}` }, "See the changes and pick", icon("chev", "sm")),
    h("div", { class: "actions split" }, reject, apply),
    sends ? h("p", { class: "final" }, icon("send", "sm"), `${plural(sends, "item", "items")} can't be undone once out.`) : null);
  return card;
}

screens.changesets = async (id) => {
  const cs = await api("GET", `/owner/changesets/${id}`);
  const open = cs.status === "proposed";
  const picks = cs.preview.map(() => true);
  const apply = h("button", { class: "primary", type: "button" });
  const label = () => {
    const n = picks.filter(Boolean).length;
    apply.textContent = n === cs.preview.length ? "Apply all" : `Apply ${plural(n, "change", "changes")}`;
    apply.disabled = n === 0;
  };
  label();
  apply.setAttribute("data-needs-net", "1");
  apply.onclick = () => act(apply, () => api("POST", `/owner/changesets/${cs.id}/apply`,
    { selected: picks.map((v, i) => (v ? i : null)).filter((v) => v !== null) }),
    (out) => { clearQuestionPushes((id) => id === cs.id, "changesets"); appliedToast(out, cs.preview.length); location.hash = "#/inbox"; });
  const reject = h("button", { type: "button" }, "Deny");
  reject.onclick = () => rejectChangeset(reject, cs);
  const sends = cs.preview.filter((p) => p.decision !== "run" && p.tier !== "reversible").length;
  return [topbar("Changeset", "#/inbox"),
    head(cs.title, open ? `${plural(cs.preview.length, "change", "changes")} proposed by the agent. Untick what you don't want.` : null,
      open ? null : statusLabel(cs.status)),
    h("div", { class: "surface cs-detail" }, cs.preview.map((p, i) => {
      const box = open ? h("input", { type: "checkbox", checked: true, "aria-label": `Include: ${p.summary}`,
        onchange: (ev) => { picks[i] = ev.target.checked; label(); } }) : null;
      return h("div", { class: "cs-item" }, box ? h("label", { class: "pick" }, box) : null,
        h("div", { class: "grow" }, csHead(p),
          (p.warnings || []).length ? h("div", { class: "warns" }, p.warnings.map((w) => warnRow(w))) : null,
          p.decision === "run" ? diffBlock(quiet(p.diff)) : payloadList(p.args || {}, { skip: ["id"] })));
    })),
    open ? h("div", { class: "decision-bar" },
      sends ? h("p", { class: "note" }, icon("send", "sm"), `${plural(sends, "item", "items")} can't be undone once out. The rest can be reverted.`)
        : h("p", { class: "note" }, "Everything here can be reverted from the journal."),
      h("div", { class: "actions split" }, reject, apply)) : null];
};

// ------------------------------------------------ inbox

function attentionCard(item) {
  let card = null;
  const done = h("button", { class: "quiet", type: "button" }, item.kind === "plugin" ? "Hide until it breaks again" : "Done");
  done.onclick = () => act(done, () => api("POST", `/owner/attention/${item.id}/dismiss`), () => dismiss(card, "done"));
  const open = item.url ? h("a", { class: "button quiet", href: item.url.replace(/^.*\/app\//, "./") }, "Open") : null;
  // the same message several times (a backup failing night after night) comes as one card with its count
  const times = item.count > 1 ? h("span", { class: "times", title: `${item.count} times` }, `×${item.count}`) : null;
  const seen = item.count > 1 ? `${item.count} times, first ${when(item.first)}, last ${when(item.created)}` : when(item.created);
  card = h("article", { class: "attention", "aria-label": item.count > 1 ? `${item.title}, ${item.count} times` : item.title }, icon("warn"),
    h("div", { class: "grow" }, h("h3", { class: "title" }, item.title, times),
      item.detail ? h("p", { class: "detail" }, item.detail) : null,
      h("p", { class: "meta mt-1" }, seen),
      h("div", { class: "actions" }, open, done)));
  return card;
}

// ------------------------------------------------ an agent's question (doorman ask-owner)

// The push for a question opens #/inbox/question/<id>, a network request's #/inbox/network/<id>, a
// changeset's #/changesets/<id>, a held-back item's #/quarantine/<id>. Once it is answered here, dismissed
// or gone, its push (and its buttons) leaves the tray: `done(id)` says which.
async function clearQuestionPushes(done, kind = "question") {
  try {
    const registration = "serviceWorker" in navigator && await navigator.serviceWorker.getRegistration();
    if (!registration || !registration.getNotifications) return;
    for (const n of await registration.getNotifications()) {
      const m = new RegExp(`#/(?:inbox/)?${kind}/(\\d+)$`).exec((n.data && n.data.url) || "");
      if (m && done(Number(m[1]))) n.close();
    }
  } catch (_) { /* no notifications here: nothing to clear */ }
}

// A question the agent asked when its task was unclear. The words are the agent's, never Doorman's: they sit
// in a white block under "Your agent asks", like what goes out on a send. Options answer in one tap; a typed
// answer is the owner's own text, so an address in it counts as theirs, as in a task they wrote.
function questionCard(q) {
  let card = null;
  let busy = false;
  const name = q.agent || "your agent";
  const soon = expirySoon(q.expires);
  const task = q.task ? { task_id: q.task.id, task_text: q.task.text, task_origin: q.task.origin, task_trusted: q.task.trusted } : {};

  // answered here, elsewhere or too late: the card goes either way, the toast says which
  const answer = (control, body, said) => {
    if (busy) return;
    busy = true;
    act(control, () => api("POST", `/owner/questions/${q.id}/${body ? "answer" : "dismiss"}`, body || undefined).catch((err) => {
      if (err.code === "not_found" || /already|meanwhile/.test(err.reason || "")) return { gone: sentence(err.reason || "This question is closed already") };
      throw err;
    }), (out) => {
      clearQuestionPushes((id) => id === q.id);
      if (out.gone) toast(out.gone, "info");
      else toast(body ? `${said} The agent carries on with it.` : "Dismissed. The agent decides without you.");
      dismiss(card, body ? "done" : "denied");
    }).finally(() => { busy = false; });
  };

  const options = (q.options || []).map((text, i) => {
    const b = h("button", { type: "button", "data-needs-net": "1", disabled: offline, "aria-label": `Answer “${text}”` }, text);
    b.onclick = () => answer(b, { option: i }, `Answered “${text}”.`);
    return b;
  });
  const field = h("textarea", { id: `answer-${q.id}`, rows: "2", maxlength: "1000", "data-keep": `answer-${q.id}`,
    "aria-describedby": `answer-hint-${q.id}`, placeholder: options.length ? "Something else" : "Type your answer" });
  const send = h("button", { class: "primary", type: "button", "data-needs-net": "1", disabled: offline }, "Send answer");
  send.onclick = () => {
    const said = field.value.trim();
    if (!said) { field.focus(); return; }
    answer(send, { answer: said }, "Answer sent.");
  };
  const drop = h("button", { type: "button", "data-needs-net": "1", disabled: offline }, "Dismiss");
  drop.onclick = async () => {
    if (busy) return;
    const ok = await confirmSheet("Dismiss this question?",
      "The agent gets no answer. It decides on its own, or tells you it couldn't.", "Dismiss");
    if (ok) answer(drop, null);
  };

  card = h("article", { class: "approval question", "aria-label": `Question from ${name}` },
    h("div", { class: "who" }, avatar(name), h("div", { class: "grow" },
      h("h2", { tabindex: "-1" }, "Your agent asks"),
      h("p", { class: "meta" }, `${name} · asked ${relative(q.asked)}`)),
      soon ? h("span", { class: "meta" }, soon) : null),
    h("div", { class: "asked" }, q.question),
    taskLine(task),
    options.length ? h("div", { class: "options", role: "group", "aria-label": "Answers to choose from" }, options) : null,
    h("label", { class: "field own" }, h("span", { class: "label" }, options.length ? "Or answer in your own words" : "Your answer"), field,
      h("span", { class: "hint", id: `answer-hint-${q.id}` }, "An address you type here counts as yours, as in a task you write: no new-recipient warning for it.")),
    h("div", { class: "actions split" }, drop, send));
  return card;
}

// ------------------------------------------------ an agent asks for network access (doorman egress request)

// What each answer lets through. "Always" puts the target on the allow list for every agent, so it takes a
// passkey check like adding to the trust list; the other three are a tap.
const NETWORK_DONE = {
  once: (r) => `Allowed ${r.target} for an hour.`,
  task: (r) => `Allowed ${r.target} until task ${r.task.id} ends.`,
  always: (r) => `${r.target} is on your allow list now.`,
  deny: (r) => `Denied. The agent hears it can't reach ${r.target}.`,
};

// The proxy blocked something and the agent asks to get through. The target is the stakes, so it leads;
// the reason is the agent's own words, in a white block like a question's; what it read lately says what
// it could take along.
function networkCard(r) {
  let card = null;
  let busy = false;
  const name = r.agent || "Your agent";
  const soon = expirySoon(r.expires);
  const task = r.task ? { task_id: r.task.id, task_text: r.task.text, task_origin: r.task.origin, task_trusted: r.task.trusted } : {};

  const decide = (control, decision) => {
    if (busy) return;
    busy = true;
    const call = decision === "always" ? sensitive : api;
    act(control, () => call("POST", `/owner/egress/requests/${r.id}/decide`, { decision }).catch((err) => {
      if (err.code === "not_found" || /already|meanwhile/.test(err.reason || "")) return { gone: sentence(err.reason || "This request is closed already") };
      throw err;
    }), (out) => {
      clearQuestionPushes((id) => id === r.id, "network");
      if (out.gone) toast(out.gone, "info");
      else toast(NETWORK_DONE[decision](r));
      dismiss(card, decision === "deny" ? "denied" : "done");
    }).finally(() => { busy = false; });
  };
  const button = (decision, label, hint, cls = "") => {
    const b = h("button", { type: "button", class: cls, "data-needs-net": "1", disabled: offline },
      hint ? [h("span", {}, label), h("span", { class: "hint" }, hint)] : label);
    b.onclick = () => decide(b, decision);
    return b;
  };

  const blocked = r.blocked ? h("p", { class: "net-line" }, h("b", {}, `Blocked ${clock(r.blocked.ts)}`), ` · ${sentence(r.blocked.detail)}`) : null;
  card = h("article", { class: "approval question network", "aria-label": `${name} asks for network access to ${r.target}` },
    h("div", { class: "who" }, avatar(name), h("div", { class: "grow" },
      h("h2", { tabindex: "-1" }, h("span", { class: "lead" }, `${name} asks for network access to`), h("span", { class: "target mono" }, r.target)),
      h("p", { class: "meta" }, `Asked ${relative(r.asked)}${soon ? ` · ${soon.toLowerCase()}` : ""}`))),
    h("div", { class: "asked" }, h("span", { class: "label" }, "The agent says"), r.reason),
    blocked,
    r.reads ? h("p", { class: "net-line" }, h("b", {}, "It read"), ` ${r.reads.replace(/^read /, "")}`) : null,
    taskLine(task),
    h("div", { class: "options", role: "group", "aria-label": "Allow for longer" },
      r.task ? button("task", "For this task", `Until task ${r.task.id} ends`) : null,
      button("always", "Always", "Adds it to your allow list, for every agent")),
    h("div", { class: "actions split" }, button("deny", "Deny"), button("once", "Allow once", null, "primary")),
    h("span", { class: "final" }, "Allow once lets it through for an hour."));
  return card;
}

const pushSupported ="serviceWorker" in navigator && "PushManager" in window && "Notification" in window;

// Sends that carry the same thing to different people, like one note to four new addresses. Grouped so a
// burst can be refused at once.
const DESTINATION_KEYS = ["to", "cc", "bcc", "recipient", "recipients", "chat", "phone", "iban", "attendees", "url"];
function bursts(approvals) {
  const groups = new Map();
  for (const a of approvals) {
    if (a.entries.length !== 1) continue;
    const e = a.entries[0];
    const rest = Object.fromEntries(Object.entries(e.args || {}).filter(([k]) => !DESTINATION_KEYS.includes(k)).sort());
    const key = `${e.tool} ${JSON.stringify(rest)}`;
    groups.set(key, [...(groups.get(key) || []), a]);
  }
  return [...groups.values()].filter((g) => g.length > 1);
}

function burstRow(group) {
  const e = group[0].entries[0];
  const seen = [...new Set(group.flatMap((a) => (a.entries[0].untrusted_destinations || [])
    .map((d) => (d.first_seen || {}).label).filter(Boolean)))];
  const what = e.outgoing && e.outgoing.title ? `“${e.outgoing.title}”` : "The same thing";
  const fresh = group.filter((a) => (a.entries[0].untrusted_destinations || []).length).length;
  const times = group.map((a) => new Date(a.created).getTime()).filter((t) => !Number.isNaN(t));
  const mins = times.length ? Math.max(1, Math.round((Math.max(...times) - Math.min(...times)) / 60000)) : null;
  const deny = h("button", { type: "button" }, `Deny all ${group.length}`);
  deny.onclick = () => denyWithNote(deny, group, {}, () => route());
  return h("div", { class: "burst", role: "group", "aria-label": `${group.length} sends of ${what}` },
    h("div", { class: "burst-head" }, icon("warn"), h("strong", {}, `${what} goes to ${plural(group.length, "address", "addresses")}`), deny),
    h("div", { class: "grow" },
      h("span", { class: "line" }, [
        fresh ? (seen.length ? `${fresh === group.length ? "All" : fresh} new, first seen in “${seen.join("”, “")}”. `
          : `The agent wrote ${fresh === group.length ? "these addresses" : `${fresh} of them`} itself. `) : "",
        mins ? `Asked for within ${mins === 1 ? "a minute" : `${mins} minutes`}.` : ""].join("")),
      e.task_text ? h("span", { class: "line" }, h("b", {}, taskHead(e)), ` · ${e.task_text}`) : null,
      h("a", { class: "more-link", href: reviewHref(group) }, `Read all ${group.length} and decide`, icon("chev", "sm"))));
}

// inBurst: the burst banner already says who's new and which task asked. sameTask: on the task's own screen.
function waitRow(a, inBurst = false, sameTask = false) {
  const m = mcpOf(a);
  const to = m ? m.server : approvalRecipient(a) || (undoable(a) ? plural(a.entries.length, "change", "changes") : plural(a.entries.length, "send", "sends"));
  const e = a.entries[0];
  const what = m ? mcpAction(m) : a.entries.length > 1 ? plural(a.entries.length, "send", "sends")
    : e.outgoing && e.outgoing.title ? `${e.outgoing.label || "Copy of"} “${e.outgoing.title}”` : e.summary;
  const fresh = a.entries.some((x) => (x.untrusted_destinations || []).length);
  const paused = a.entries.some((x) => x.key_paused);
  // inside a burst the banner already says who's new and which task asked; said once
  return h("a", { class: "row-item link-row", href: `#/approvals/${a.id}`, "aria-label": `${m ? "Run on" : "Send to"} ${to}: ${what}${paused ? ". Its agent is paused" : ""}${fresh ? ". New recipient" : ""}` },
    avatar(to), h("div", { class: "grow" }, h("div", { class: "primary-text" }, to), h("div", { class: "secondary-text" }, what),
      !inBurst && !sameTask && e.task_text ? h("div", { class: "secondary-text task-mini" }, `${taskHead(e)} · ${e.task_text}`) : null,
      paused ? h("div", { class: "secondary-text look danger" }, "Its agent is paused: a honeytoken") : null,
      !inBurst && fresh ? h("div", { class: "secondary-text look" }, "New recipient") : null), icon("chev", "sm"));
}

// The emergency stop, one tap from the inbox and at the top of More.
function stopButton() {
  if (doormanPaused) return null;
  const b = h("button", { class: "quiet stop", type: "button" }, icon("power", "sm"), "Stop agents");
  b.onclick = () => stopAgents(b);
  return b;
}

// Two ways to stop: Pause keeps the keys, so Resume brings the agent straight back; Revoke all keys is for a
// key that may have leaked, and the agent then needs a new key and its setup again.
async function stopAgents(button) {
  const how = await sheet({ title: "Stop the agents?",
    body: [h("p", {}, "Pause refuses every agent call at once. Waiting sends stay for you to decide, and the keys stay, so Resume brings the agent back."),
      h("p", {}, "Revoke all keys if a key may have leaked. The agent then needs a new key, set up again from a computer.")],
    actions: [{ label: "Revoke all keys", value: "revoke", kind: "danger" }, { label: "Pause agents", value: "pause", kind: "danger solid" }] });
  if (how === "pause") act(button, () => api("POST", "/owner/pause"), () => { toast("Paused. The keys stay; Resume brings the agent back."); route(); });
  else if (how === "revoke") revokeAllKeys(button, false);
}

async function revokeAllKeys(button, ask = true) {
  if (ask && !(await confirmSheet("Revoke every agent key?", "Every agent loses access at once and waiting sends are cancelled. To bring one back, create a new key and run its setup again.", "Revoke all keys", "danger solid"))) return;
  act(button, () => api("POST", "/owner/kill"), () => { toast("Every agent key is revoked."); route(); });
}

const inboxCount = (d) => d.approvals.length + d.changesets.length + (d.attention || []).length
  + (d.questions || []).length + (d.network || []).length;

// A new Doorman's Inbox, until the first agent key exists: the two things to do, where "Nothing waiting for
// you" would stand. The key can come first; a connected plugin only ticks its line.
function firstSteps(steps) {
  const row = (attrs, mark, title, text) => h("a", { class: "row-item link-row", ...attrs }, icon(mark),
    h("div", { class: "grow" }, h("div", { class: "primary-text" }, title), h("div", { class: "secondary-text" }, text)), icon("chev"));
  // opens the sheet right here; More > Agents has the same button
  const key = row({ href: "#/more", role: "button" }, "agent", "Give your agent a key",
    "You get a message to paste into your agent. It sets itself up from there.");
  key.onclick = (e) => { e.preventDefault(); newKey(key); };
  return section("Get started", h("div", { class: "list" },
    row({ href: "#/plugins", class: `row-item link-row${steps.plugin ? " done" : ""}` }, steps.plugin ? "check" : "plugins",
      "Connect an account or MCP server", steps.plugin ? "Done. More are under Plugins." : "Mail, a calendar, Notion and more, under Plugins."),
    key),
    { note: "Two steps until your agent works through Doorman. What it wants to send then shows up here." });
}

// #/inbox/question/<id> (a question's push) or #/inbox/network/<id> (a network request's): that one comes
// first, above the oldest send.
screens.inbox = async (...args) => {
  const data = await api("GET", "/owner/inbox");
  const attention = data.attention || [];
  const questions = data.questions || [];
  const network = data.network || [];
  setBadge(inboxCount(data));
  const changes = data.approvals.filter(undoable).length, sends = data.approvals.length - changes;
  const waiting = [sends ? plural(sends, "send", "sends") : null, changes ? plural(changes, "change", "changes") : null,
    data.changesets.length ? plural(data.changesets.length, "changeset", "changesets") : null,
    questions.length ? plural(questions.length, "question", "questions") : null,
    network.length ? plural(network.length, "network request", "network requests") : null].filter(Boolean);
  clearPushes(null, new Set(data.approvals.map((a) => a.id)));  // decided elsewhere or expired: out of the tray
  const open = new Set(questions.map((q) => q.id));
  const openNet = new Set(network.map((r) => r.id));
  clearQuestionPushes((id) => !open.has(id));
  clearQuestionPushes((id) => !openNet.has(id), "network");
  const openSets = new Set(data.changesets.map((c) => c.id));
  clearQuestionPushes((id) => !openSets.has(id), "changesets");
  const target = args[0] === "question" && open.has(Number(args[1])) ? ["question", Number(args[1])]
    : args[0] === "network" && openNet.has(Number(args[1])) ? ["network", Number(args[1])] : null;
  const first_ = (kind) => (a, b) => (target && target[0] === kind ? (b.id === target[1]) - (a.id === target[1]) : 0) || a.id - b.id;
  const asked = [...questions].sort(first_("question")).map(questionCard);
  const netCards = [...network].sort(first_("network")).map(networkCard);
  const queue = [...data.approvals].sort((a, b) => a.id - b.id);
  const [first, ...rest] = queue;
  const out = [head("Inbox", waiting.length ? `${[waiting.slice(0, -1).join(", "), waiting[waiting.length - 1]].filter(Boolean).join(" and ")} waiting for you` : null, stopButton())];
  if (data.first_steps) out.push(firstSteps(data.first_steps));  // on top: without an agent only notices can wait
  // the one a push opened goes on top, its kind with it; the rest follow the oldest send
  const shown = target && target[0] === "network" ? [netCards, asked] : [asked, netCards];
  const cards = shown.flat().length ? h("div", { class: "questions" }, shown) : null;
  if (target) {  // from its push: on top, with the focus on it for a screen reader
    out.push(cards);
    requestAnimationFrame(() => { const at = shown[0][0].querySelector("h2"); if (at.isConnected) at.focus({ preventScroll: true }); });
  }
  if (first) out.push(approvalCard(first));
  if (!target) out.push(cards);
  const groups = bursts(queue);
  const grouped = new Set(groups.flat().map((a) => a.id));
  if (rest.length) out.push(section("Also waiting", h("div", { class: "waiting" }, groups.map(burstRow), rest.map((a) => waitRow(a, grouped.has(a.id))))));
  if (data.changesets.length) out.push(section(data.changesets.length > 1 ? "Changesets" : "Changeset", h("div", { class: "stack" }, data.changesets.map(changesetCard))));
  if (attention.length) out.push(section("Needs attention", attention.map(attentionCard), { count: attention.length }));
  if (!data.first_steps && !inboxCount(data)) {
    const pushOff = pushSupported && Notification.permission !== "granted";
    out.push(h("div", { class: "empty" }, h("div", { class: "mark" }, icon("check", "lg")),
      h("h2", {}, "Nothing waiting for you"),
      h("p", {}, "When the agent wants to send something, proposes changes or asks you something, it shows up here."),
      h("div", { class: "actions" }, pushOff ? h("a", { class: "button primary", href: "#/more" }, icon("bell"), "Turn on notifications") : null,
        h("a", { class: "button", href: "#/journal" }, "See what it did"))));
  }
  return out;
};

// A cron schedule in words, for the common shapes; anything else is said as it is.
function cronText(cron) {
  const [m, hr, dom, mon, dow] = String(cron || "").trim().split(/\s+/);
  const time = /^\d+$/.test(m) && /^\d+$/.test(hr) ? `${hr.padStart(2, "0")}:${m.padStart(2, "0")}` : null;
  const days = { "*": "Every day", "1-5": "Weekdays", "0,6": "Weekends", "6,0": "Weekends", "1": "Mondays", "2": "Tuesdays",
    "3": "Wednesdays", "4": "Thursdays", "5": "Fridays", "6": "Saturdays", "0": "Sundays", "7": "Sundays" };
  if (time && dom === "*" && mon === "*" && days[dow]) return `${days[dow]} at ${time}`;
  if (/^\d+$/.test(m) && hr === "*" && dom === "*" && mon === "*" && dow === "*") return `Every hour at minute ${m}`;
  return `On the schedule ${cron}`;
}

// ------------------------------------------------ journal

function conflictView(c) {
  const show = (state, field) => {
    if (!state) return "(doesn't exist)";
    const v = state[field];
    return v === undefined || v === null || v === "" ? "(empty)" : Array.isArray(v) ? v.join(", ") : String(v);
  };
  const fields = (c.fields || []).filter((f) => f !== "the whole object");
  if (!fields.length) return h("p", {}, `${c.reason || "It changed since the agent's action"}.`);
  return [h("p", {}, "Someone changed it again after the agent did. Reverting puts back the \"before\" value and overwrites what's there now."),
    h("div", { class: "conflict" }, fields.map((f) => h("div", {}, h("div", { class: "field-name" }, f),
      h("dl", {}, h("dt", {}, "Before"), h("dd", {}, show(c.before, f)), h("dt", {}, "Agent"), h("dd", {}, show(c.after, f)),
        h("dt", {}, "Now"), h("dd", { class: "now" }, show(c.now, f))))))];
}

function revertSummary(out) {
  const parts = [`Reverted ${out.reverted.length}`];
  if (out.conflicts.length) parts.push(`${out.conflicts.length} changed since (revert those one by one)`);
  if ((out.failed || []).length) parts.push(`${out.failed.length} failed`);
  return parts.join(", ");
}

function previewSheet(preview, title) {
  const n = preview.will_revert.length;
  if (!n) return sheet({ title: "Nothing to revert", body: h("p", {}, preview.skipped.length
    ? `${plural(preview.skipped.length, "action", "actions")} in that range already left the system and can't be reverted.`
    : "Nothing in that range can be undone."), cancel: "Close" });
  return sheet({ title, body: h("dl", { class: "counts" },
      h("div", {}, h("dt", {}, "Actions reverted"), h("dd", {}, n)),
      preview.also_reverts.length ? h("div", {}, h("dt", {}, "Later changes to the same items, also reverted"), h("dd", {}, preview.also_reverts.length)) : null,
      h("div", {}, h("dt", {}, "Skipped: already sent"), h("dd", {}, preview.skipped.length))),
    actions: [{ label: `Revert ${plural(n, "action", "actions")}`, value: true, kind: "danger solid" }] });
}

const TIER = { reversible: "can be undone", irreversible: "send", payment: "payment", read: "read", config: "setting" };
// Fields that change with every write and tell the owner nothing.
const NOISE_FIELDS = new Set(["id", "uid", "etag", "href", "updated", "created", "modified", "updated_at", "created_at",
  "last_modified", "dtstamp", "sequence"]);
const quiet = (lines) => (lines || []).filter((l) => !NOISE_FIELDS.has(String(l.field || "").toLowerCase()));

const shownStatus = (e) => (e.status === "unknown" && e.checking ? "checking" : e.status);

// A send as a receipt: who, what, any words of its own, when, what happened, and the entry it is filed under.
function receipt(e) {
  const a = e.args || {};
  const to = recipientsOf(e).join(", ");
  const m = /^(?:Send|Sent)\s+(.+?)\s+to\s+\S.*$/.exec(e.summary || "");
  const what = m ? m[1].charAt(0).toUpperCase() + m[1].slice(1) : e.summary || e.tool;
  const own = TEXT_KEYS.find((k) => typeof a[k] === "string" && a[k].trim());
  const state = e.status === "done" ? "Sent" : (STATUS[shownStatus(e)] || [e.status])[0];
  const rows = [["To", to], ["What", what], own ? ["Message", a[own]] : null, a.subject ? ["Subject", a.subject] : null,
    ["When", when(e.ts)], ["State", state], ["Entry", h("span", { class: "hash" }, (e.hash || "").slice(0, 7))]].filter((r) => r && r[1]);
  return h("dl", { class: "payload" }, rows.map(([k, v]) => h("div", {}, h("dt", {}, k), h("dd", {}, v))));
}

function commitRow(e) {
  const sent = e.kind === "action" && SENDS.includes(e.tier);
  const failedish = ["failed", "denied", "rejected", "expired"].includes(e.status);
  const node = e.status === "reverted" ? "reverted" : failedish ? "danger" : e.status === "done" ? (sent ? "send" : "ok") : "";
  const what = (e.summary || e.tool).replace(/\((\S+ \S+ \S+ \S+ \S+)\)/, (all, cron) => `(${cronText(cron)})`);
  const revert = e.revertable ? h("button", { class: "quiet revert", type: "button", "aria-label": `Revert: ${what}` }, icon("undo", "sm"), "Revert") : null;
  if (revert) revert.onclick = () => act(revert, async () => {
    let out = await sensitive("POST", `/owner/journal/${e.id}/revert`, {});
    if (out.conflicts.length) {
      const force = await sheet({ title: "Changed since the agent's action", body: conflictView(out.conflicts[0]),
        actions: [{ label: "Overwrite and revert", value: true, kind: "danger solid" }] });
      if (!force) return out;
      out = await sensitive("POST", `/owner/journal/${e.id}/revert`, { force: true });
    }
    return out;
  }, (out) => {
    const failed = (out.failed || [])[0];
    if (failed) toast(`Revert failed: ${failed.reason}`, "error");
    else if (out.reverted.length) toast(`Reverted ${out.reverted.length}`);
    else if (!out.conflicts.length) toast((out.skipped[0] || {}).reason || "Nothing reverted");
    route().then(() => {
      const dot = view.querySelector(`.commit[data-id="${e.id}"] .node`);
      if (dot && !reducedMotion.matches) play(dot, [{ transform: "scale(1.7)" }, { transform: "none" }], { duration: 420 });
    });
  });
  const kind = e.kind === "action" ? TIER[e.tier] || e.tier : e.kind === "config" ? "setting" : e.kind;
  const state = sent && e.status === "done" ? sendTag() : e.status !== "done" ? statusLabel(shownStatus(e)) : null;
  // a send is a receipt of what went out; a change is its diff without the bookkeeping fields
  const detail = sent ? receipt(e) : diffBlock(quiet(e.diff));
  const details = h("details", {},
        h("summary", {}, h("div", { class: "line1" }, h("span", { class: "text" }, what)),
          h("div", { class: "line2" }, h("time", { class: "time", datetime: e.ts }, clock(e.ts)), state)),
        h("div", { class: "detail" }, detail, e.follow_up ? h("p", { class: "note" }, e.follow_up) : null,
          sent ? null : h("p", { class: "meta" }, `${kind.charAt(0).toUpperCase()}${kind.slice(1)} · entry `, h("span", { class: "hash" }, (e.hash || "").slice(0, 7)))));
  // the chevron mirrors the line's own toggle; the summary is the control screen readers and keyboards use
  const trail = revert || h("span", { class: "trail", "aria-hidden": "true", onclick: () => { details.open = !details.open; } }, icon("chev", "sm chev"));
  return h("li", { class: `commit${e.status === "reverted" ? " is-reverted" : ""}`, "data-id": e.id },
    h("span", { class: `node ${node}`, "aria-hidden": "true" }),
    h("div", { class: "body" }, details, e.error ? h("p", { class: "error" }, e.error) : null),
    trail);
}

function localInputValue(date) {
  const pad = (n) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

// Journal shows changes (with diffs and revert), reads (who saw what) or the feed (what agents are told).
// The choice sticks per tab; #/journal/feed (a link from a task) picks one too.
const JOURNAL_VIEWS = ["changes", "reads", "feed"];
function journalSwitch(current) {
  const pick = (view, label) => {
    const b = h("button", { class: `seg${current === view ? " on" : ""}`, "aria-pressed": current === view ? "true" : "false" }, label);
    b.onclick = () => {
      try { sessionStorage.setItem("journalView", view); } catch (_) { /* private mode */ }
      if (location.hash !== "#/journal") location.hash = "#/journal"; else route();
    };
    return b;
  };
  return h("div", { class: "segs", role: "group", "aria-label": "Show" }, pick("changes", "Changes"), pick("reads", "Reads"), pick("feed", "Feed"));
}

const paramText = (params) => Object.entries(params || {}).map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`).join("  ");

const READ_TAGS = { denied: ["Refused", "danger"], quarantined: ["Held back", "send"], failed: ["Failed", "danger"] };
function readRow(r, tasks) {
  const bad = !["ok", "unscanned"].includes(r.status);
  const task = r.task_id ? tasks[r.task_id] : null;
  const hiddenCount = r.labels.filter((it) => it.hidden).length;
  const meta = [clock(r.ts), r.key_name || `key ${r.key_id}`, bad ? null : plural(r.items, "item", "items"),
    hiddenCount ? `${hiddenCount} hidden` : null].filter(Boolean).join(" · ");
  const summary = h("summary", {}, h("div", { class: "grow" },
      h("div", { class: "line1" }, h("span", { class: "mono rname" }, r.name),
        bad ? h("span", { class: `tag ${(READ_TAGS[r.status] || READ_TAGS.failed)[1]}` }, (READ_TAGS[r.status] || READ_TAGS.failed)[0]) : null,
        r.status === "unscanned" ? h("span", { class: "tag off" }, "Not scanned") : null),
      paramText(r.params) ? h("div", { class: "rparams mono" }, paramText(r.params)) : null,
      h("div", { class: "meta" }, meta, task ? [" · ", h("span", {}, `task ${task.id}`)] : null)),
    r.labels.length || bad || r.status === "unscanned" ? icon("chev", "sm chev") : null);
  if (!r.labels.length && !bad && r.status !== "unscanned") return h("li", { class: "read" }, h("div", { class: "read-flat" }, summary.childNodes[0]));
  return h("li", { class: "read" }, h("details", {}, summary,
    h("div", { class: "content" },
      bad || r.status === "unscanned" ? h("p", { class: "error" }, r.error || r.status) : null,
      task ? h("p", { class: "meta" }, `Task ${task.id}: ${task.text}`) : null,
      r.labels.length ? h("ul", { class: "read-items" }, r.labels.map((it) => h("li", {},
        h("span", {}, it.label || it.ref || "(no title)"), it.hidden ? h("span", { class: "tag hidden-tag" }, "Agent saw a placeholder") : null,
        it.quarantined ? h("span", { class: "tag send hidden-tag" }, "Held back") : null,
        it.from || it.when ? h("span", { class: "meta" }, [it.from, it.when ? it.when.replace("T", " ") : null].filter(Boolean).join(" · ")) : null))) : null,
      r.items > r.labels.length ? h("p", { class: "meta" }, `and ${r.items - r.labels.length} more`) : null)));
}

async function readsScreen() {
  const data = await api("GET", "/owner/reads?limit=150");
  const list = h("div", {});
  let last = null, tasks = { ...data.tasks };
  const render = (rows) => {
    for (const r of rows) {
      const d = (r.ts || "").slice(0, 10);
      if (!last || last.day !== d) {
        last = { day: d, ol: h("ol", { class: "reads" }) };
        list.append(h("section", { class: "group" }, h("div", { class: "group-head" }, h("h2", {}, day(d))), last.ol));
      }
      last.ol.append(readRow(r, tasks));
    }
  };
  render(data.reads);
  const more = h("button", { class: "quiet" }, "Show older");
  let oldest = data.reads.length ? data.reads[data.reads.length - 1].id : null;
  more.hidden = data.reads.length < 150;
  more.onclick = () => act(more, () => api("GET", `/owner/reads?limit=150&before=${oldest}`), (out) => {
    Object.assign(tasks, out.tasks);
    render(out.reads);
    if (out.reads.length) oldest = out.reads[out.reads.length - 1].id;
    more.hidden = out.reads.length < 150;
  });
  const keep = data.keep_days ? `Kept ${data.keep_days} days.` : "Kept until you delete it.";
  return [head("Journal", `Who read what, newest first. Reads change nothing, so there's nothing to revert. ${keep}`, stopButton()),
    h("div", { class: "tools" }, journalSwitch("reads")),
    data.reads.length ? [list, h("div", { class: "actions" }, more)] : h("div", { class: "empty" },
      h("div", { class: "mark" }, icon("journal", "lg")), h("h2", {}, "No reads yet"),
      h("p", {}, "Every time an agent reads your mail, calendar or anything else through Doorman, it shows up here."))];
}

// ------------------------------------------------ the feed: what agents are told (GET /owner/events)

// Each event as one line in words. Plugin events carry what a stranger wrote (a sender, a subject): it's
// only ever text here, like everything else in the app.
const short = (text, n = 120) => { const t = String(text ?? "").replace(/\s+/g, " ").trim(); return t.length > n ? `${t.slice(0, n - 1)}…` : t; };
const sender = (d) => d.from_name || d.from || "someone";
const courseOf = (d) => d.course || "A course";
const dueWords = (d) => (d.days === 0 ? "today" : d.days === 1 ? "tomorrow" : d.date ? day(String(d.date).slice(0, 10)).replace(/^(Today|Yesterday)$/, (w) => w.toLowerCase()) : "soon");
const PLUGIN_EVENT_LINES = {
  new_mail: (d) => `New mail from ${sender(d)}${d.subject ? `: ${d.subject}` : ""}`,
  new_message: (d) => `${sender(d)}${d.chat_name || d.topic ? ` in ${d.chat_name || d.topic}` : ""}${d.text ? `: ${d.text}` : " wrote to you"}`,
  invite_received: (d) => `${sender(d)} invited you${d.summary ? `: ${d.summary}` : ""}${d.start ? `, ${when(d.start)}` : ""}`,
  event_soon: (d) => `${d.minutes ? `In ${d.minutes} min` : "Soon"}: ${d.summary || "an entry"}${d.location ? `, ${d.location}` : ""}`,
  new_file: (d) => `New or changed file: ${d.path || "a file"}`,
  announcement: (d) => `${courseOf(d)}: new announcement${d.title ? ` “${d.title}”` : ""}`,
  grade: (d) => `${courseOf(d)}: ${d.change === "changed" ? "a grade changed" : "new grade"}${d.item ? ` for ${d.item}` : ""}`,
  deadline_soon: (d) => `${courseOf(d)}: ${d.title || "a deadline"}, due ${dueWords(d)}`,
};
// Doorman's own events name the action they're about as the journal does (`summary`), else by its number.
const DECISIONS = { approved: "You approved", declined: "You denied", edited: "You edited", closed: "Closed, the agent changed it" };
const SEND_RESULTS = { sent: ["Went out", ""], done: ["Done", ""], failed: ["Failed", "danger"], unknown: ["Outcome unknown", "warn"], cancelled: ["Cancelled", ""] };
const CHANGESET_RESULTS = { applied: "applied", partially_applied: "partly applied", declined: "denied by you" };
const taskWords = (id, tasks) => (tasks[id] ? `Task ${id}: ${short(tasks[id].text, 80)}` : `Task ${id}`);
const actionOf = (d, e) => e.summary || (d.approval_id ? `approval #${d.approval_id}` : d.tool || "an action");
const DOORMAN_EVENT_LINES = {
  approval_decided: (d, tasks, e) => `${DECISIONS[d.decision] || d.decision}: ${actionOf(d, e)}${d.decision === "edited" && d.replaced_by
    ? ` (now #${d.replaced_by.approval_id})` : ""}`,
  approval_expired: (d, tasks, e) => `Expired unanswered: ${actionOf(d, e)}`,
  approval_ask_again: (d, tasks, e) => `You still want it, so the agent was asked again: ${actionOf(d, e)}`,
  // a send that went out is filed as "Sent …" already
  send_result: (d, tasks, e) => (d.status === "sent" && /^Sent\b/.test(e.summary || "") ? e.summary
    : `${(SEND_RESULTS[d.status] || [d.status])[0]}: ${e.summary || d.tool}`),
  entry_reverted: (d, tasks, e) => `Reverted: ${e.summary || d.tool}`,
  changeset_decided: (d) => `Changeset #${d.changeset_id} ${CHANGESET_RESULTS[d.status] || d.status}`,
  task_created: (d, tasks) => `New ${taskWords(d.task_id, tasks).replace(/^T/, "t")}`,
  task_cancelled: (d, tasks) => `${taskWords(d.task_id, tasks)} ended: ${d.reason === "closed by the owner" ? "you closed it" : d.reason}`,
  reminder_due: (d, tasks) => `Reminder due: ${taskWords(d.task_id, tasks).replace(/^T/, "t")}`,
  question_answered: (d) => `The reader ${d.status === "answered" ? "answered" : d.status === "failed" ? "couldn't answer" : "didn't answer in time"} question #${d.question_id}`,
  owner_answered: (d) => (d.status === "answered" ? `You answered: “${short(d.answer, 80)}”` : d.status === "dismissed" ? "You dismissed a question" : "A question to you expired unanswered"),
};

function eventLine(e, tasks) {
  const lines = e.source === "plugin" ? PLUGIN_EVENT_LINES : DOORMAN_EVENT_LINES;
  const make = lines[e.type];
  if (make) return short(make(e.data || {}, tasks, e));
  const what = eventWords(e.type);
  return short(`${what.charAt(0).toUpperCase()}${what.slice(1)}${e.ref ? ` (${e.ref})` : ""}`);
}

// How much of a plugin's events agents get by your switches now; nothing is said when they get all of it.
const AGENTS_GET = { where: "Agents: only that it came", none: "Agents don't get these", off: "Plugin off" };
// The plugin's name in words; its own name too when there are two of a kind (two mailboxes).
const sourceName = (e, plugins) => {
  if (e.source === "doorman") return "Doorman";
  const type = plugins[e.plugin] || e.plugin;
  const twins = Object.values(plugins).filter((t) => t === type).length > 1;
  return twins ? `${pluginTitle(type)} (${e.plugin})` : pluginTitle(type);
};

function eventRow(e, ctx, opts = {}) {
  const d = e.data || {};
  const result = e.type === "send_result" ? SEND_RESULTS[d.status] : null;
  const links = [];
  if (e.task_id && e.task_id !== opts.inTask) links.push(h("a", { class: "inline-link", href: `#/task/${e.task_id}` }, `Task ${e.task_id}`));
  const [kind, id] = String(e.ref || "").split(":");
  if (kind === "approval" && e.source === "doorman") links.push(h("a", { class: "inline-link", href: `#/approvals/${id}` }, "Approval"));
  if (kind === "changeset" && e.source === "doorman") links.push(h("a", { class: "inline-link", href: `#/changesets/${id}` }, "Changeset"));
  const forKeys = e.source === "doorman" && ctx.keys.length > 1
    ? (e.keys || []).map((k) => (ctx.keys.find((x) => x.id === k) || { name: `key ${k}` }).name).join(", ") : null;
  const meta = [opts.inTask ? when(e.ts) : clock(e.ts), sourceName(e, ctx.plugins), forKeys ? `for ${forKeys}` : null].filter(Boolean).join(" · ");
  const extra = [
    d.note ? h("p", { class: "note" }, `Your note: ${d.note}`) : null,
    d.comment ? h("p", { class: "note" }, `Your comment: ${d.comment}`) : null,
    e.type === "owner_answered" && d.question ? h("p", { class: "note" }, `Asked: ${short(d.question, 200)}`) : null,
    d.error ? h("p", { class: "error" }, d.error) : null,
    ...(e.triggers || []).map((t) => h("p", { class: "note" }, `Trigger “${t.name}” made `,
      t.task_id === opts.inTask ? "this task" : h("a", { class: "inline-link", href: `#/task/${t.task_id}` }, `task ${t.task_id}`))),
  ].filter(Boolean);
  const agents = e.source === "plugin" && AGENTS_GET[e.agents] ? h("span", { class: "tag off" }, AGENTS_GET[e.agents]) : null;
  return h("li", { class: `feed-item${e.source === "plugin" ? " from-plugin" : ""}`, "data-id": e.id },
    h("span", { class: `node ${result && result[1] === "danger" ? "danger" : e.source === "plugin" ? "in" : ""}`, "aria-hidden": "true" }),
    h("div", { class: "body" },
      h("p", { class: "text" }, eventLine(e, ctx.tasks)),
      h("div", { class: "meta" }, meta, links.map((a) => [" · ", a])),
      agents ? h("div", { class: "tags" }, agents) : null,
      extra));
}

// Where each agent key stands: everything above its marker came after it last looked.
function readMarker(names) {
  return h("li", { class: "feed-mark", role: "separator" }, h("span", {}, `${names.join(", ")} read up to here`));
}

function keyLines(keys, latest) {
  if (!keys.length) return h("p", { class: "meta feed-keys" }, "No agent key yet: nobody follows the feed.");
  return h("div", { class: "feed-keys" }, keys.map((k) => h("p", { class: "meta" }, icon("agent", "sm"), " ",
    k.cursor === null ? `${k.name} hasn't asked for the feed yet. An agent that runs all the time follows it with doorman events --follow.`
      : k.cursor >= latest ? `${k.name} has seen everything${k.seen ? ` (last looked ${relative(k.seen)})` : ""}.`
        : `${k.name}${k.seen ? ` last looked ${relative(k.seen)} and` : ""} hasn't seen what's above its line yet.`)));
}

const FEED_PAGE = 50;
async function feedScreen() {
  let source = "all";
  try { source = sessionStorage.getItem("feedSource") || "all"; } catch (_) { /* private mode */ }
  const page = (before) => api("GET", `/owner/events?limit=${FEED_PAGE}${source !== "all" ? `&source=${source}` : ""}${before ? `&before=${before}` : ""}`);
  const data = await page(null);
  const ctx = { keys: data.keys, plugins: data.plugins, tasks: { ...data.tasks } };
  // a key's marker sits above the newest event it has seen; one that has seen everything needs none
  const marks = data.keys.filter((k) => k.cursor !== null && k.cursor < data.latest);
  const list = h("div", {});
  let last = null;
  const placed = new Set();
  const render = (events) => {
    for (const e of events) {
      const d = (e.ts || "").slice(0, 10);
      if (!last || last.day !== d) {
        last = { day: d, ol: h("ol", { class: "feed" }) };
        list.append(h("section", { class: "group" }, h("div", { class: "group-head" }, h("h2", {}, day(d))), last.ol));
      }
      const here = marks.filter((k) => !placed.has(k.id) && e.id <= k.cursor);
      if (here.length) { here.forEach((k) => placed.add(k.id)); last.ol.append(readMarker(here.map((k) => k.name))); }
      last.ol.append(eventRow(e, ctx));
    }
  };
  render(data.events);
  const older = h("button", { class: "quiet", type: "button" }, "Show older");
  let oldest = data.events.length ? data.events[data.events.length - 1].id : null;
  older.hidden = !data.more;
  older.onclick = () => act(older, () => page(oldest), (out) => {
    Object.assign(ctx.tasks, out.tasks);
    render(out.events);
    if (out.events.length) oldest = out.events[out.events.length - 1].id;
    older.hidden = !out.more;
  });

  const filter = h("select", { class: "filter", "aria-label": "Show events from" },
    [["all", "All"], ["plugin", "Plugins"], ["doorman", "Doorman"]].map(([value, label]) =>
      h("option", { value, selected: source === value }, label)));
  filter.onchange = () => { try { sessionStorage.setItem("feedSource", filter.value); } catch (_) { /* private mode */ } route(); };
  const days = data.keep_days ? `Kept ${plural(data.keep_days, "day", "days")}.` : "";
  return [head("Journal", `What your agents are told, newest first: what came in through your plugins, and what Doorman told them about their requests and tasks. ${days}`, stopButton()),
    h("div", { class: "tools" }, journalSwitch("feed"), h("span", { class: "spacer" }), filter),
    keyLines(data.keys, data.latest),
    data.events.length ? [list, h("div", { class: "actions" }, older)] : h("div", { class: "empty" },
      h("div", { class: "mark" }, icon("bell", "lg")), h("h2", {}, source === "all" ? "Nothing in the feed yet" : "Nothing from here yet"),
      h("p", {}, "New mail, messages and course news your plugins report show up here, and what Doorman tells your agents about their sends and tasks."))];
}

screens.journal = async (sub) => {
  let view = "changes";
  if (JOURNAL_VIEWS.includes(sub)) try { sessionStorage.setItem("journalView", sub); } catch (_) { /* private mode */ }
  try { view = sessionStorage.getItem("journalView") || "changes"; } catch (_) { /* private mode */ }
  if (JOURNAL_VIEWS.includes(sub)) view = sub;
  if (view === "reads") return readsScreen();
  if (view === "feed") return feedScreen();
  let showDenied = false;
  try { showDenied = sessionStorage.getItem("showDenied") === "1"; } catch (_) { /* private mode */ }
  const PAGE = 150;
  const page = (before) => api("GET", `/owner/journal?limit=${PAGE}${showDenied ? "&include_denied=true" : ""}${before ? `&before=${before}` : ""}`);
  const [data, week] = await Promise.all([page(null), api("GET", "/owner/week").catch(() => null)]);

  // Groups by task, else by day. "Show older" appends the next page: rows of a group already shown join
  // it, the rest start new groups below.
  const list = h("div", {});
  const groups = new Map();
  const tasks = { ...data.tasks };
  const render = (entries) => {
    for (const e of entries) {
      const key = e.task_id ? `task-${e.task_id}` : `day-${(e.ts || "").slice(0, 10)}`;
      let g = groups.get(key);
      if (!g) {
        const task = e.task_id ? tasks[e.task_id] : null;
        g = { ol: h("ol", { class: "timeline" }), count: 0, meta: h("p", { class: "meta" }) };
        groups.set(key, g);
        g.task = task;
        list.append(h("section", { class: "group" },
          h("div", { class: "group-head" }, h("div", { class: "grow" }, h("h2", {}, task ? task.text : day((e.ts || "").slice(0, 10))), g.meta),
            task ? revertTaskButton(task, "Revert task") : null), g.ol));
      }
      g.ol.append(commitRow(e));
      g.count++;
      if (e.revertable) g.ol.classList.add("has-revert");
      fill(g.meta, g.task ? [h("a", { class: "inline-link", href: `#/task/${g.task.id}` }, `Task ${g.task.id}`), " · ", taskState(g.task)[0]]
        : plural(g.count, "action", "actions"));
    }
  };
  render(data.entries);
  const older = h("button", { class: "quiet", type: "button" }, "Show older");
  let oldest = data.entries.length ? data.entries[data.entries.length - 1].id : null;
  older.hidden = data.entries.length < PAGE;
  older.onclick = () => act(older, () => page(oldest), (out) => {
    Object.assign(tasks, out.tasks);
    render(out.entries);
    if (out.entries.length) oldest = out.entries[out.entries.length - 1].id;
    older.hidden = out.entries.length < PAGE;
    if (!out.entries.length) toast("That's everything: nothing older in the journal.");
  });

  const rollback = h("button", { class: "rollback", type: "button", "aria-label": "Roll back to a time" }, icon("clock", "sm"), h("span", { class: "words" }, "Roll back"));
  rollback.onclick = async () => {
    const since = h("input", { type: "datetime-local", id: "since", value: localInputValue(new Date(Date.now() - 3600e3)) });
    const go = await sheet({ title: "Roll back everything since", actions: [{ label: "Preview", value: true, kind: "primary" }],
      body: [h("p", {}, "Reverts every action that can be undone, from this moment on. Sent emails and messages are skipped: they already left."),
        h("label", { class: "field" }, h("span", { class: "label" }, "From"), since)] });
    if (!go) return;
    act(rollback, async () => {
      if (!since.value) throw new Error("Pick a time first.");
      const iso = new Date(since.value).toISOString().slice(0, 19) + "+00:00";
      const preview = await api("POST", "/owner/revert", { since: iso, preview: true });
      if (!(await previewSheet(preview, `Roll back to ${when(new Date(since.value).toISOString())}?`))) return null;
      return api("POST", "/owner/revert", { since: iso });
    }, (out) => { if (out) { toast(revertSummary(out)); route(); } });
  };
  const verify = h("button", { type: "button" }, icon("shield", "sm"), "Check");
  verify.onclick = () => act(verify, () => api("GET", "/owner/journal/verify"),
    (r) => toast(r.ok ? "Journal intact: nothing was changed after the fact."
      : `Something in the journal was changed after the fact, from entry ${r.first_bad_entry} on. Restore it from a backup.`, r.ok ? "" : "error"));
  const denied = toggle(showDenied, "Show refused calls", async (on) => {
    try { sessionStorage.setItem("showDenied", on ? "1" : "0"); } catch (_) { /* private mode */ }
    route();
  }, { hint: "Calls Doorman refused. They changed nothing." });
  const options = h("div", { class: "journal-options", id: "journal-options", hidden: !showDenied },
    week ? h("div", { class: "opt" }, h("a", { href: "#/status" }, weekLine(week))) : null,
    denied,
    h("div", { class: "opt" }, h("span", {}, "Check that nothing was changed after the fact"), verify));
  const more = h("button", { class: "icon-only", type: "button", "aria-label": "More journal options", "aria-expanded": String(showDenied), "aria-controls": "journal-options" }, icon("more"));
  more.onclick = () => { const open = options.hidden; options.hidden = !open; more.setAttribute("aria-expanded", String(open)); };

  return [head("Journal", data.entries.length ? "What the agent did, newest first. Tap a line for the details." : null, stopButton()),
    h("div", { class: "tools" }, journalSwitch("changes"), h("span", { class: "spacer" }), rollback, more),
    options,
    data.entries.length ? [list, h("div", { class: "actions" }, older)] : h("div", { class: "empty" }, h("div", { class: "mark" }, icon("journal", "lg")), h("h2", {}, "No actions yet"),
      h("p", {}, "Everything the agent changes or sends lands here, with a way back."))];
};

// ------------------------------------------------ tasks

// Reverts everything a task did that can be undone, after a preview of what that is. Sent things are skipped.
function revertTaskButton(task, label) {
  const button = h("button", { class: "quiet", type: "button", "aria-label": `${label}: ${task.text}` }, icon("undo", "sm"), label);
  button.onclick = () => act(button, async () => {
    const preview = await api("POST", "/owner/revert", { task_id: task.id, preview: true });
    if (!(await previewSheet(preview, "Revert this task?"))) return null;
    return api("POST", "/owner/revert", { task_id: task.id });
  }, (out) => { if (out) { toast(revertSummary(out)); route(); } });
  return button;
}

// A task the owner closed is stored as failed (that's what the agent hears); here it says who ended it.
const taskState = (t) => (t.closed_by_owner ? ["Closed by you", "quiet"] : STATUS[t.status] || [t.status, ""]);
const taskStatus = (t) => h("span", { class: `status ${taskState(t)[1]}` }, taskState(t)[0]);

function taskOrigin(t) {
  const other = strangerTask(t.origin, t.trusted);
  if (other) return `Not written by you: ${other}`;
  return String(t.origin || "").startsWith("routine:") ? `Your routine “${t.origin.slice(8)}”` : "From you";
}

// A task is its text. What the agent may do on it is set once, in each plugin's Tools.
screens.tasks = async () => {
  const data = await api("GET", "/owner/tasks");
  const text = h("textarea", { id: "task", placeholder: "e.g. Keep Thursday morning free and tell the team", "data-keep": "new-task" });
  const add = h("button", { class: "primary block" }, "Give to agent");
  add.onclick = () => act(add, () => {
    if (!text.value.trim()) throw new Error("Write the task first.");
    return api("POST", "/owner/tasks", { text: text.value });
  }, () => { forget(text); toast("Task handed to the agent"); route().then(() => arrive(view.querySelector("article.task"))); });

  return [head("Tasks", null, stopButton()),
    h("div", { class: "surface pad-4" },
      h("label", { class: "field" }, h("span", { class: "label" }, "New task"), text,
        h("span", { class: "hint" }, "The agent may do what each plugin's Tools allow. Changes it proposes wait for you. You get a notification when it's done.")),
      h("div", { class: "mt-3" }, add)),
    section("Recent", data.tasks.length ? h("div", { class: "list" }, data.tasks.map((t) => h("article", { class: "task row-item as-block" },
      h("p", { class: "text" }, t.text),
      h("div", { class: "actions task-meta" }, taskStatus(t), h("span", { class: "meta" }, `${taskOrigin(t)} · ${when(t.created)}`)),
      t.report ? h("div", { class: "report clamp" }, t.report) : null,
      h("div", { class: "actions quiet-row" },
        t.status === "pending" ? null : h("a", { class: "button quiet", href: `#/task/${t.id}` }, "See what it did"),
        ["pending", "claimed"].includes(t.status) ? closeButton(t) : null))))
      : h("div", { class: "empty compact" }, h("p", {}, "No tasks yet. Tasks you write here are trusted: the agent may act on them.")))];
};

function closeButton(task) {
  const claimed = task.status === "claimed";
  const button = h("button", { class: "quiet plain", type: "button" }, claimed ? "Close task" : "Cancel task");
  button.onclick = async () => {
    if (!(await confirmSheet(claimed ? "Close this task?" : "Cancel this task?",
      claimed ? "The agent stops working on it and is free for the next task. What it already did stays in the journal, where you can revert it."
        : "No agent will pick it up.", claimed ? "Close task" : "Cancel task"))) return;
    act(button, () => api("POST", `/owner/tasks/${task.id}/close`, {}), () => { toast(claimed ? "Task closed" : "Task cancelled"); route(); });
  };
  return button;
}

// One task: what was asked, how it ended, what is still waiting for you, and everything it did, with a way back.
screens.task = async (id) => {
  // the feed's part is extra: the task screen still opens without it
  const [d, told, net] = await Promise.all([api("GET", `/owner/tasks/${id}`),
    api("GET", `/owner/events?task_id=${encodeURIComponent(id)}&limit=${TASK_EVENTS}`).catch(() => null),
    api("GET", `/owner/egress/log?task_id=${encodeURIComponent(id)}&limit=${TASK_NET}`).catch(() => null)]);
  const t = d.task;
  const open = ["pending", "claimed"].includes(t.status);
  const what = h("div", { class: "surface pad-4" },
    h("p", { class: "task-text" }, t.text),
    h("div", { class: "actions task-meta" }, taskStatus(t),
      h("span", { class: "meta" }, `${taskOrigin(t)} · ${when(t.created)}${t.claimed_by ? ` · taken by ${t.claimed_by}` : ""}`)),
    t.report ? h("div", { class: "report" }, h("span", { class: "label" }, t.closed_by_owner ? "Why it ended" : "The agent's report"), t.report)
      : t.status === "claimed" ? h("p", { class: "meta mt-2" }, "The agent is working on it.") : null,
    open ? h("div", { class: "actions quiet-row" }, closeButton(t)) : null);
  const waiting = d.approvals.length ? section("Waiting for you",
    h("div", { class: "waiting" }, d.approvals.map((a) => waitRow(a, false, true))),
    { count: d.approvals.length, end: d.approvals.length > 1 ? h("a", { class: "more-link", href: reviewHref(d.approvals) }, "Read all and decide", icon("chev", "sm")) : null }) : null;
  const did = d.entries.length ? h("section", { class: "group" },
    h("div", { class: "group-head" }, h("div", { class: "grow" }, h("h2", {}, "What it did"),
      h("p", { class: "meta" }, plural(d.entries.length, "entry", "entries"), " · newest first")),
      d.revertable ? revertTaskButton(t, "Revert this task") : null),
    h("ol", { class: `timeline${d.entries.some((e) => e.revertable) ? " has-revert" : ""}` }, d.entries.map(commitRow)))
    : h("div", { class: "empty compact" }, h("p", {}, open ? "Nothing changed or sent for it yet." : "It changed and sent nothing."));
  return [topbar(`Task ${t.id}`, "#/tasks"), head(`Task ${t.id}`), what, waiting, did, taskNetwork(net && net.rows), taskEvents(told, t.id)];
};

// What the agent sent to the internet for this task (network watch), under the tool call that did it;
// connections while no call ran come last, under "Outside tool calls".
const TASK_NET = 200;
function taskNetwork(rows) {
  if (!rows || !rows.length) return null;
  const groups = new Map();
  for (const r of rows) {
    const k = r.call ? `call:${r.call.id}` : "outside";
    if (!groups.has(k)) groups.set(k, { call: r.call || null, rows: [] });
    groups.get(k).rows.push(r);
  }
  const ordered = [...groups.values()].sort((a, b) => !a.call - !b.call);  // calls first, newest first
  const blocked = rows.filter((r) => r.decision === "deny").length;
  return h("section", { class: "group" },
    h("div", { class: "group-head" }, h("div", { class: "grow" }, h("h2", {}, "Network"),
      h("p", { class: "meta" }, `${rows.length >= TASK_NET ? `The newest ${rows.length}` : plural(rows.length, "connection", "connections")}${blocked ? ` · ${blocked} blocked` : ""} · newest first`)),
      h("a", { class: "more-link", href: "#/network" }, "All", icon("chev", "sm"))),
    h("div", { class: "stack" }, ordered.map((g) => h("div", { class: "list" },
      h("div", { class: "net-call" }, g.call
        ? [h("span", { class: "tname" }, g.call.tool), g.call.summary ? h("span", { class: "summary" }, g.call.summary) : null]
        : h("span", { class: "tname plain" }, "Outside tool calls")),
      g.rows.map((r) => netRow(r, !!g.call))))));
}

// What the agent was told about this task, from the feed: the event a trigger made it from, the task
// itself, your decisions on its sends and their results. Compact; the rest of the feed is a tap away.
const TASK_EVENTS = 20;
function taskEvents(told, taskId) {
  if (!told || !told.events.length) return null;
  const ctx = { keys: told.keys, plugins: told.plugins, tasks: told.tasks };
  return h("section", { class: "group" },
    h("div", { class: "group-head" }, h("div", { class: "grow" }, h("h2", {}, "What the agent was told"),
      h("p", { class: "meta" }, told.more ? `The newest ${told.events.length}` : plural(told.events.length, "event", "events"), " · newest first")),
      h("a", { class: "more-link", href: "#/journal/feed" }, "Whole feed", icon("chev", "sm"))),
    h("ol", { class: "feed" }, told.events.map((e) => eventRow(e, ctx, { inTask: taskId }))));
}

// ------------------------------------------------ plugins

// A plugin's setup steps from its manifest: [text](https://…) becomes a link, `x` code, **x** bold.
function inlineText(text) {
  const out = [];
  const pattern = /\[([^\]]+)\]\((https:\/\/[^)\s]+)\)|`([^`]+)`|\*\*([^*]+)\*\*|\*([^*]+)\*/g;
  let last = 0;
  for (const m of text.matchAll(pattern)) {
    out.push(text.slice(last, m.index));
    if (m[1]) out.push(h("a", { href: m[2], target: "_blank", rel: "noopener" }, m[1]));
    else if (m[3]) out.push(h("code", {}, m[3]));
    else if (m[4]) out.push(h("strong", {}, m[4]));
    else out.push(h("em", {}, m[5]));
    last = m.index + m[0].length;
  }
  out.push(text.slice(last));
  return out;
}

function setupSteps(steps) {
  if (!steps || !steps.length) return null;
  return h("ol", { class: "setup-steps" }, steps.map((step) => h("li", {}, inlineText(step))));
}

// Connect a plugin to an account (Google): open the consent page, then paste back the address the
// browser ends on. The redirect goes to a loopback address, so on a phone that page doesn't load.
function loginBox(p) {
  const provider = p.login_provider || "Google";
  const box = h("div", { class: "body", "data-part": "login" }, h("p", { class: "meta" }, "Checking the connection…"));
  api("GET", `/owner/plugins/${p.name}/login`).then((st) => {
    if (st.connected) {
      const off = h("button", { class: "quiet plain", type: "button" }, "Disconnect");
      off.onclick = async () => {
        if (await confirmSheet(`Disconnect ${p.name}?`, provider === "Google" ? "Doorman forgets the login and revokes it at Google." : `Doorman forgets the ${provider} login.`, "Disconnect", "danger solid"))
          act(off, () => api("POST", `/owner/plugins/${p.name}/logout`), () => { toast("Disconnected"); rebuildCard(p.name); });
      };
      box.replaceChildren(h("div", { class: "actions spread" },
        h("span", { class: "tag ok" }, icon("check", "sm"), st.account ? `Connected as ${st.account}` : "Connected"), off));
      return;
    }
    if (!st.ready) {
      box.replaceChildren(...[warnRow(st.error || "Not set up yet: fill in its settings and credentials below."),
        p.setup && p.setup.length ? disclose("How to set it up", setupSteps(p.setup)) : null].filter(Boolean));  // replaceChildren would print "null"
      if (p.enabled && p.setup && p.setup.length) box.querySelector("details").open = true;
      return;
    }
    const start = h("button", { class: "primary" }, "Connect account");
    const pasted = h("input", { type: "url", placeholder: "http://127.0.0.1:…/?state=…&code=…", autocomplete: "off", class: "mono" });
    const finish = h("button", { class: "primary" }, "Finish");
    const link = h("a", { class: "button primary", target: "_blank", rel: "noopener" }, `1. Open ${provider} sign-in`);
    const step2 = h("div", { hidden: true },
      link,
      h("label", { class: "field" }, h("span", { class: "label" }, "2. Paste the address you end up on"), pasted,
        h("span", { class: "hint" }, `Allow access on ${provider}'s page. It ends on a page that doesn't load (localhost): copy that page's whole address.`)),
      h("div", { class: "mt-3" }, finish));
    // a link the owner taps, because browsers block windows opened after a network round trip
    start.onclick = () => act(start, () => sensitive("POST", `/owner/plugins/${p.name}/login/start`), (out) => {
      if (!out.auth_url) { toast("Connected. This server needs no sign-in."); rebuildCard(p.name); return; }
      link.href = out.auth_url;
      step2.hidden = false;
      start.hidden = true;
    });
    finish.onclick = () => act(finish, () => api("POST", `/owner/plugins/${p.name}/login/finish`, { url: pasted.value }),
      (out) => { toast(`Connected${out.account ? " as " + out.account : ""}`); rebuildCard(p.name); });
    box.replaceChildren(h("div", { class: "actions spread" }, h("span", { class: "tag danger" }, "Not connected"), start), step2);
  }).catch((err) => box.replaceChildren(warnRow(err.message, "danger")));
  return box;
}

// A QR code from rows of "0"/"1" (1 dark), with the quiet zone readers need. Black on white in both themes:
// phones don't read an inverted code.
function qrCode(qr, label) {
  const NS = "http://www.w3.org/2000/svg", quiet = 4, n = qr.size + 2 * quiet;
  let d = "";
  qr.rows.forEach((row, y) => {
    for (const run of row.matchAll(/1+/g)) d += `M${run.index + quiet} ${y + quiet}h${run[0].length}v1h-${run[0].length}z`;
  });
  const svg = document.createElementNS(NS, "svg");
  for (const [k, v] of Object.entries({ viewBox: `0 0 ${n} ${n}`, class: "qr", role: "img", "aria-label": label, "shape-rendering": "crispEdges" }))
    svg.setAttribute(k, v);
  const bg = document.createElementNS(NS, "rect");
  bg.setAttribute("width", n); bg.setAttribute("height", n); bg.setAttribute("fill", "#fff");
  const marks = document.createElementNS(NS, "path");
  marks.setAttribute("d", d); marks.setAttribute("fill", "#000");
  svg.append(bg, marks);
  return svg;
}

// Link a plugin as a device of the owner's account (login: link, WhatsApp). The sidecar asks WhatsApp for a
// code: a QR code to scan, or a pairing code to type on the phone. The box asks again every few seconds while
// linking, and keeps what you typed: only the code itself is swapped when WhatsApp sends a new one.
function linkBox(p) {
  const provider = p.login_provider || "WhatsApp";
  const box = h("div", { class: "body", "data-part": "login" }, h("p", { class: "meta" }, "Checking the connection…"));
  let shown = null, linking = false, timer = null;
  const load = () => api("GET", `/owner/plugins/${p.name}/login`).then(show)
    .catch((err) => { delete box.dataset.busy; box.replaceChildren(warnRow(err.message, "danger")); });
  const start = (button, body) => act(button, () => sensitive("POST", `/owner/plugins/${p.name}/login/start`, body),
    (out) => { linking = true; show({ ready: true, link: out.link }); });
  const phoneForm = (label) => {
    const phone = h("input", { type: "tel", placeholder: "+49 151 23456789", autocomplete: "tel", class: "mono" });
    const go = h("button", { type: "button" }, "Get a code");
    go.onclick = () => start(go, { phone: phone.value.trim() });
    return disclose(label, [h("label", { class: "field" }, h("span", { class: "label" }, `Your ${provider} number`), phone,
      h("span", { class: "hint" }, `With the country code. ${provider} sends that phone a notification; there you type the code shown here.`)),
      h("div", { class: "mt-3" }, go)]);
  };

  function show(st) {
    clearTimeout(timer);
    if (st.connected) {
      delete box.dataset.busy;
      if (linking) toast(`Linked${st.account ? " as " + st.account : ""}`);
      linking = false; shown = null;
      const off = h("button", { class: "quiet plain", type: "button" }, "Unlink");
      off.onclick = async () => {
        if (await confirmSheet(`Unlink ${p.name}?`, `Doorman logs this device out of your ${provider}: it leaves Linked devices on your phone. To use it again, link it again.`, "Unlink", "danger solid"))
          act(off, () => api("POST", `/owner/plugins/${p.name}/logout`), () => { toast("Unlinked"); rebuildCard(p.name); });
      };
      box.replaceChildren(...[h("div", { class: "actions spread" },
        h("span", { class: "tag ok" }, icon("check", "sm"), st.account ? `Linked as ${st.account}` : "Linked"), off),
        st.sync_running === false && st.last_error ? warnRow(st.last_error) : null].filter(Boolean));
      return;
    }
    if (!st.ready) {
      delete box.dataset.busy; shown = null;
      box.replaceChildren(...[warnRow(st.error || "Not set up yet: fill in its settings below."),
        p.setup && p.setup.length ? disclose("How to set it up", setupSteps(p.setup)) : null].filter(Boolean));
      return;
    }
    const link = st.link || { state: "idle" };
    if (!["starting", "scan", "enter_code", "linked"].includes(link.state)) {
      delete box.dataset.busy; shown = null;
      const go = h("button", { class: "primary" }, `Link ${provider}`);
      go.onclick = () => start(go, {});
      box.replaceChildren(...[h("div", { class: "actions spread" }, h("span", { class: "tag danger" }, "Not linked"), go),
        link.state === "failed" && link.error ? warnRow(link.error, "danger") : null,
        phoneForm("Can't scan a code here? Link with your phone number")].filter(Boolean));
      return;
    }
    box.dataset.busy = "1";  // refreshCard leaves it alone
    timer = setTimeout(() => { if (box.isConnected) load(); }, 3000);
    if (shown && shown.state === link.state) {  // the same step: swap the code, keep the rest
      if (link.state === "scan") shown.code.replaceChildren(qrCode(link.qr, `QR code to link ${provider}`));
      if (link.state === "enter_code") shown.code.textContent = link.pair_code;
      return;
    }
    const code = h("div", {});
    let parts;
    if (link.state === "starting") parts = [h("p", { class: "meta" }, `Asking ${provider} for a code…`)];
    else if (link.state === "scan") {
      code.append(qrCode(link.qr, `QR code to link ${provider}`));
      parts = [h("p", {}, `On your phone: ${provider} → Settings → Linked devices → Link a device, then point it at this code.`),
        code, h("p", { class: "meta" }, `${provider} sends a new code every 20 seconds or so; this page keeps up.`),
        phoneForm("Can't scan it? Link with your phone number")];
    } else if (link.state === "enter_code") {
      code.className = "pair-code"; code.textContent = link.pair_code;
      const qr = h("button", { class: "quiet plain", type: "button" }, "Scan a QR code instead");
      qr.onclick = () => start(qr, {});
      parts = [h("p", {}, `On the phone with +${link.phone}: tap the ${provider} notification (or Linked devices → Link a device → Link with phone number instead) and type this code.`),
        code, qr];
    } else parts = [h("div", { class: "actions" }, h("span", { class: "tag ok" }, icon("check", "sm"), "Linked")),
      h("p", { class: "meta" }, `${provider} is sending your recent chats. Doorman starts reading once that's done, usually in a minute or two.`)];
    shown = { state: link.state, code };
    box.replaceChildren(...parts);
  }

  load();
  return box;
}

// The password again, where a passkey Doorman shows the passkey prompt. Null when the owner cancels.
async function askPassword() {
  const field = h("input", { type: "password", autocomplete: "current-password", required: true });
  const ok = await sheet({ title: "Confirm with your password", actions: [{ label: "Confirm", value: true, kind: "primary" }],
    body: (done) => {
      field.addEventListener("keydown", (ev) => { if (ev.key === "Enter") { ev.preventDefault(); done(true); } });
      return [h("p", {}, "This change needs your password again. Doorman then doesn't ask for a few minutes."),
        h("label", { class: "field" }, h("span", { class: "label" }, "Password"), field)];
    } });
  return ok ? field.value : null;
}

// Changes to plugins and credentials need a passkey check from the last few minutes (the password, where
// Doorman signs in with one). When Doorman asks for one ("reauth"), prompt once and try again.
async function sensitive(method, path, body) {
  try {
    return await api(method, path, body);
  } catch (err) {
    if (err.code !== "reauth") throw err;
    if (signIn === "password") {
      const password = await askPassword();
      if (password === null) throw new Error("Not confirmed with your password. Nothing changed.");
      await api("POST", "/owner/auth/reauth/password", { password });
    } else {
      const signed = await signWithPasskey("/owner/auth/reauth/options");
      await api("POST", "/owner/auth/reauth/verify", signed);
    }
    return api(method, path, body);
  }
}

const shown = (v) => (v === undefined || v === null ? "" : typeof v === "object" ? JSON.stringify(v) : String(v));

// One text field per setting the plugin documents (plus any already set). Lists are typed as [a, b].
function configFields(help, current, keep) {
  const keys = [...new Set([...Object.keys(help || {}), ...Object.keys(current || {})])];
  const inputs = {};
  const rows = keys.map((key) => {
    inputs[key] = h("input", { type: "text", value: shown((current || {})[key]), autocomplete: "off", autocapitalize: "off", spellcheck: "false",
      "data-keep": keep && `${keep}:${key}` });
    return h("label", { class: "field" }, h("span", { class: "label" }, keyWords(key), keyHint(key)), inputs[key],
      help && help[key] ? h("span", { class: "hint" }, help[key]) : null);
  });
  const read = () => Object.fromEntries(Object.entries(inputs).map(([k, el]) => [k, el.value.trim()]));
  return { rows, read, inputs };
}

// Secrets: typed once, sent to the vault, never shown again. The app only learns whether each is set.
function credentialRows(p) {
  const fromLogin = p.login === "oauth" ? ["refresh_token", "account", "access_token", "access_expires", "oauth"] : [];  // Connect sets these
  const optional = p.optional_credentials || [];
  const names = [...new Set([...(p.credentials || []), ...optional, ...(p.credentials_set || [])])].filter((k) => !fromLogin.includes(k));
  return names.map((key) => {
    let isSet = (p.credentials_set || []).includes(key);
    const words = credentialWords(key);
    const input = h("input", { type: "password", autocomplete: "new-password", "aria-label": words, "data-keep": `cred:${p.name}:${key}` });
    const status = h("span", { class: "part" });
    const clear = h("button", { class: "quiet plain", type: "button" }, "Remove");
    const clearRow = h("div", { class: "quiet-row tight" }, clear);
    const show = () => {  // only this row changes: the other fields keep what you typed
      status.replaceChildren(isSet ? h("span", { class: "tag ok" }, icon("check", "sm"), "Set")
        : optional.includes(key) ? h("span", { class: "meta" }, "Optional") : h("span", { class: "tag danger" }, "Missing"));
      input.placeholder = isSet ? "Stored. Type to replace" : "Not set";
      clearRow.hidden = !isSet;
    };
    show();
    const save = h("button", {}, "Save");
    save.onclick = () => act(save, () => {
      if (!input.value) throw new Error("Type the value first.");
      return sensitive("POST", `/owner/instances/${p.name}/credentials`, { key, value: input.value });
    }, () => { input.value = ""; isSet = true; show(); toast(`${words} stored in the vault`); refreshCard(p.name); });
    clear.onclick = async () => {
      if (await confirmSheet(`Remove ${p.name}'s ${words.toLowerCase()}?`, "It's deleted from the vault. The plugin stops working until you set it again.", "Remove", "danger solid"))
        act(clear, () => sensitive("POST", `/owner/instances/${p.name}/credentials`, { key, value: null }),
          () => { isSet = false; show(); toast(`${words} removed from the vault`); refreshCard(p.name); });
    };
    return h("div", { class: "cred" }, h("div", { class: "line1" }, h("strong", {}, words, keyHint(key)), status),
      h("div", { class: "inline-form" }, input, save), clearRow);
  });
}

function disclose(summary, content, opts = {}) {
  return h("details", { class: "disclose", "data-keep": opts.keep }, h("summary", {}, h("span", { class: "grow" }, summary),
    opts.meta ? h("span", { class: "meta" }, opts.meta) : null, icon("chev", "sm chev")), h("div", { class: "content" }, content));
}

function settingsBox(p) {
  const creds = credentialRows(p);
  const parts = [h("h3", { class: "subhead" }, "Credentials"), creds.length ? creds : h("p", { class: "meta" }, "This plugin needs none.")];
  const form = configFields(p.config_help, p.config, `config:${p.name}`);
  // an MCP server's tools are allowed one by one instead ("Always allow")
  const noApproval = p.type === "mcp" ? null : localSwitch(p.no_approval, "Run its sends without asking me", "Only while every check passes. File transfers and public links still ask. Journaled, not revertable.", `no_approval:${p.name}`);
  const save = h("button", { class: "primary" }, "Save settings");
  save.onclick = () => act(save, () => sensitive("POST", `/owner/instances/${p.name}/config`,
    { config: form.read(), no_approval: noApproval ? noApproval.box.checked : undefined }), () => {
      // what's in the fields is stored now; refreshCard then shows it the way Doorman keeps it
      for (const el of Object.values(form.inputs)) el.defaultValue = el.value;
      if (noApproval) noApproval.box.defaultChecked = noApproval.box.checked;
      toast("Saved"); refreshCard(p.name);
    });
  const remove = h("button", { class: "quiet plain", type: "button" }, "Remove plugin");
  remove.onclick = async () => {
    if (await confirmSheet(`Remove ${p.name}?`, "Its credentials are deleted too. Its journal stays, and what it kept on the server (a mail archive, a file index) is set aside, not deleted.", "Remove plugin", "danger solid"))
      act(remove, () => sensitive("POST", `/owner/instances/${p.name}/remove`), (out) => {
        toast(out && out.data_kept_in ? `Removed. What it kept is in data/${out.data_kept_in} on the server.` : "Removed"); route(); });
  };
  parts.push(h("h3", { class: "subhead mt-5" }, "Settings"), form.rows,
    form.rows.length ? h("p", { class: "meta mt-2" }, "For a list, write [a, b].") : null,
    noApproval ? noApproval.row : null, h("div", { class: "actions spread" }, remove, save));
  return disclose("Settings and credentials", parts, { keep: `settings:${p.name}` });
}

// A plugin type to set up (again, under another name, if one runs already).
function availableRow(t) {
  const keep = `add:${t.type}`;
  const name = h("input", { type: "text", value: t.in_use ? "" : t.type, placeholder: t.in_use ? "a second one, e.g. work" : "",
    autocomplete: "off", autocapitalize: "off", spellcheck: "false", "data-keep": `${keep}:name` });
  const form = configFields(t.config, {}, `${keep}:config`);
  const secrets = {};
  const secretRows = (t.credentials || []).filter((k) => !(t.login === "oauth" && k === "refresh_token")).map((key) => {
    secrets[key] = h("input", { type: "password", autocomplete: "new-password", "data-keep": `${keep}:cred:${key}` });
    return h("label", { class: "field" }, h("span", { class: "label" }, credentialWords(key), keyHint(key)), secrets[key]);
  });
  const noApproval = localSwitch(false, "Run its sends without asking me", "Only while every check passes. File transfers and public links still ask. Journaled, not revertable.", `${keep}:no_approval`);
  const add = h("button", { class: "primary block" }, icon("plus", "sm"), `Add ${t.type}`);
  add.onclick = () => act(add, () => {
    if (!name.value.trim()) throw new Error("Give it a name first.");
    return sensitive("POST", "/owner/instances", {
      name: name.value.trim(), type: t.type, config: form.read(), no_approval: noApproval.box.checked,
      credentials: Object.fromEntries(Object.entries(secrets).map(([k, el]) => [k, el.value])),
    });
  }, () => { toast(`Added ${name.value.trim()}`); forget(row); route(); });
  const row = h("details", { class: "disclose", "data-keep": keep },
    h("summary", {}, tile({ glyph: PLUGIN_GLYPHS[t.type] || "plugins" }),
      h("span", { class: "grow" }, h("span", { class: "primary-text as-block" }, pluginTitle(t.type)),
        h("span", { class: "meta as-block regular" }, t.description)), icon("chev", "sm chev")),
    h("div", { class: "content" },
      t.setup && t.setup.length ? [h("h3", { class: "subhead" }, "How to set it up"), setupSteps(t.setup)] : null,
      h("label", { class: "field" }, h("span", { class: "label" }, "Name"), name,
        h("span", { class: "hint" }, "Lower-case, e.g. mail or work. One type can run several times under different names.")),
      form.rows, form.rows.length ? h("p", { class: "meta mt-2" }, "For a list, write [a, b].") : null,
      secretRows.length ? [h("h3", { class: "subhead mt-5" }, "Credentials"), secretRows] : null,
      t.login === "oauth" ? h("p", { class: "meta mt-3" }, "After adding it, connect the account under its card.") : null,
      noApproval.row, h("div", { class: "mt-2" }, add)));
  return row;
}

// ------------------------------------------------ MCP servers

// The name a server gets from its address: mcp.notion.com -> notion.
function nameFromUrl(u) {
  try {
    const parts = new URL(u.trim()).hostname.split(".").filter((x) => !["mcp", "api", "www", "app"].includes(x));
    const base = parts.length >= 2 ? parts[parts.length - 2] : parts[0] || "";
    return base.toLowerCase().replace(/[^a-z0-9_]/g, "_").replace(/^[^a-z]+/, "").slice(0, 31);
  } catch { return ""; }
}

function mcpAddRow() {
  const url = h("input", { type: "url", inputmode: "url", placeholder: "https://mcp.example.com/mcp", autocomplete: "off", autocapitalize: "off", spellcheck: "false", "data-keep": "add:mcp:url" });
  const name = h("input", { type: "text", autocomplete: "off", autocapitalize: "off", spellcheck: "false", "data-keep": "add:mcp:name" });
  let named = false;
  name.addEventListener("input", () => { named = true; });
  url.addEventListener("input", () => { if (!named) name.value = nameFromUrl(url.value); });
  const token = h("input", { type: "password", autocomplete: "new-password", "data-keep": "add:mcp:token" });
  const add = h("button", { class: "primary block" }, icon("plus", "sm"), "Add server");
  add.onclick = () => act(add, () => {
    if (!url.value.trim()) throw new Error("Paste the server's address first.");
    if (!name.value.trim()) throw new Error("Give it a name first.");
    return sensitive("POST", "/owner/instances", { name: name.value.trim(), type: "mcp", config: { url: url.value.trim() },
      credentials: token.value ? { token: token.value } : {} });
  }, () => { toast(token.value ? `Added ${name.value.trim()}` : `Added ${name.value.trim()}. Connect it on its card.`); forget(row); route(); });
  const row = h("details", { class: "disclose", "data-keep": "add:mcp" },
    h("summary", {}, tile({ glyph: "plus" }),
      h("span", { class: "grow" }, h("span", { class: "primary-text as-block" }, "Another server"),
        h("span", { class: "meta as-block regular" }, "Any service's own MCP server, by its address.")), icon("chev", "sm chev")),
    h("div", { class: "content" },
      h("label", { class: "field" }, h("span", { class: "label" }, "Server address"), url,
        h("span", { class: "hint" }, "From the service's documentation. Use servers the service runs itself: Doorman gives the server your sign-in.")),
      h("label", { class: "field" }, h("span", { class: "label" }, "Name"), name,
        h("span", { class: "hint" }, "Lower-case, e.g. notion. The agent then sees its tools as notion.search and so on.")),
      h("label", { class: "field" }, h("span", { class: "label" }, "Access token (optional)"), token,
        h("span", { class: "hint" }, "Only for a server that takes a token instead of a sign-in. Stored in the vault, sent only to this server.")),
      h("div", { class: "mt-3" }, add)));
  return row;
}

// One well-known server (doorman/mcp/known.py): its logo, what it holds, and one button.
function knownServerRow(k, names) {
  const text = { autocomplete: "off", autocapitalize: "off", spellcheck: "false" };
  const name = h("input", { type: "text", ...text, value: names.has(k.id) ? "" : k.id,
    placeholder: names.has(k.id) ? `a second one, e.g. ${k.id}_work` : "", "data-keep": `add:known:${k.id}:name` });
  const token = k.token ? h("input", { type: "password", autocomplete: "new-password", "data-keep": `add:known:${k.id}:token` }) : null;
  const add = h("button", { class: "primary block" }, icon("plus", "sm"), `Add ${k.title}`);
  add.onclick = () => act(add, () => {
    if (!name.value.trim()) throw new Error("Give it a name first.");
    if (token && !token.value) throw new Error("Paste the access token first.");
    return sensitive("POST", "/owner/instances", { name: name.value.trim(), type: "mcp", config: { url: k.url },
      credentials: token ? { token: token.value } : {} });
  }, () => { toast(token ? `Added ${k.title}` : `Added ${k.title}. If it asks for a sign-in, connect it on its card.`); forget(row); route(); });
  const row = h("details", { class: "disclose", "data-keep": `add:known:${k.id}` },
    h("summary", {}, tile({ brand: k.id, title: k.title }),
      h("span", { class: "grow" }, h("span", { class: "primary-text as-block" }, k.title),
        h("span", { class: "meta as-block regular" }, k.about)), icon("chev", "sm chev")),
    h("div", { class: "content" },
      h("p", { class: "meta" }, `${k.title}'s own server at ${new URL(k.url).host}. Reads run freely; each write asks you first.`),
      token ? h("label", { class: "field" }, h("span", { class: "label" }, "Access token"), token, h("span", { class: "hint" }, `${k.token} Stored in the vault, sent only to this server.`)) : null,
      h("label", { class: "field" }, h("span", { class: "label" }, "Name"), name,
        h("span", { class: "hint" }, `The agent sees its tools as ${k.id}.search and so on.`)),
      h("div", { class: "mt-3" }, add)));
  return row;
}

// Why a tool counts as a read or a write, in one line.
function mcpWhy(t) {
  if (t.treat_as === "read") return "You treat it as a read: the agent uses it freely.";
  if (t.treat_as === "write") return "You treat it as a write: each call asks you first.";
  if (t.kind === "read") return "The server labels it read-only, so the agent uses it freely.";
  if (t.label === "read") return "The server labels it read-only, but only the labels it had when you connected count, so it asks first until you treat it as a read.";
  return "The server doesn't label it read-only, so each call asks you first.";
}

// One tool's choices: Always allow / Ask first again, Treat as read / write, back to the server's label.
async function mcpToolSheet(p, t) {
  const actions = [];
  if (t.treat_as) actions.push({ label: "Use the server's label", value: { treat_as: null } });
  if (t.kind === "write") {
    actions.push({ label: "Treat as read", value: { treat_as: "read" }, kind: "primary" });
  } else {
    actions.push({ label: "Treat as write", value: { treat_as: "write" }, kind: "primary" });
  }
  const body = h("div", {},
    t.changed ? h("div", { class: "mb-3" }, warnRow([h("strong", {}, "Changed since you last looked: "), mcpChangeWords(t.changed) + ".",
      t.changed.what.includes("description") && t.changed.was ? h("p", { class: "meta mt-2" }, `Before: ${t.changed.was}`) : null,
      t.allowed && t.kind === "write" ? h("p", { class: "meta mt-2" }, "It still runs without asking you. Set it to Ask me if this isn't what you allowed.") : null])) : null,
    t.destructive ? h("p", { class: "meta mb-3" }, h("span", { class: "mark danger" }, "Destructive"), "The server says it can delete or overwrite.") : null,
    t.description ? h("p", { class: "tool-about" }, t.description) : null,
    h("p", { class: "meta mt-2" }, mcpWhy(t)),
    t.kind === "write" ? h("p", { class: "meta mt-2" }, t.allowed
      ? "On Auto: it runs without asking you while every check passes. A new recipient or a full daily limit still asks."
      : "On Ask me: each call waits for your OK. Auto lets it run without asking you; none of its calls can be undone.") : null);
  const choice = await sheet({ title: t.title, body, actions });
  if (!choice) return;
  const loosens = choice.allowed === true || choice.treat_as === "read" || choice.treat_as === null;
  const send = loosens ? sensitive : api;
  try {
    await send("POST", `/owner/mcp/${p.name}/tools/${encodeURIComponent(t.name)}`, choice);
    toast(choice.allowed === true ? `“${t.title}” runs without asking you` : choice.allowed === false ? `“${t.title}” asks you first again`
      : choice.treat_as === "read" ? `“${t.title}” is a read now` : choice.treat_as === "write" ? `“${t.title}” is a write now` : "Back to the server's label");
    rebuildCard(p.name);
  } catch (err) { toast(err.message, "error"); }
}

const MCP_CHANGE = { description: "its description", parameters: "its parameters", label: "how the server labels it", back: "it was gone and is back" };
const mcpChangeWords = (c) => c.what.map((w) => MCP_CHANGE[w] || w).join(", ");
const MODE_SHORT = { "Ask me": "Ask" };  // beside a tool's name there is room for one word

// One tool on one line: its name, what it does, and its control. Tapping the name opens the sheet.
function mcpToolRow(p, t, set) {
  const short = t.name;
  const off = p.disabled_tools.includes(short) || (t.kind === "write" && p.read_only);
  const current = off ? "off" : t.kind === "read" ? "auto" : t.allowed ? "auto" : "ask";
  const marks = [t.new ? h("span", { class: "mark new" }, "New") : null,
    t.changed ? h("span", { class: "mark changed" }, "Changed") : null,
    t.destructive ? h("span", { class: "mark danger" }, "Destructive") : null];
  const open = h("button", { class: "tool-open", type: "button", "aria-label": `${t.title}: details` },
    h("span", { class: "tname" }, t.title),
    h("span", { class: "tool-desc" }, marks, t.description || (t.treat_as ? "Your choice." : "")));
  open.onclick = () => mcpToolSheet(p, t);
  const options = modeOptions(t.kind === "read" ? "read" : "irreversible").map(([mode, text, hint]) => [mode, MODE_SHORT[text] || text, hint]);
  const control = modeControl(options, current, async (mode, was) => {
    if (mode === "auto" && t.kind === "write") {
      const ok = await confirmSheet(`Always allow “${t.title}” on ${p.mcp.title}?`,
        h("div", {}, h("p", {}, "The agent's calls to it run without asking you while every check passes. A new recipient or a full daily limit still asks."),
          h("p", { class: "meta mt-2" }, "Each call is in the journal. None can be undone. Set it back to Ask me here.")),
        "Allow");
      if (!ok) return false;
    }
    if (was === "off") await set(p.name, { tool: short, tool_enabled: true });
    if (mode === "off") await set(p.name, { tool: short, tool_enabled: false });
    else if (t.kind === "write" && (mode === "auto") !== !!t.allowed)
      await (mode === "auto" ? sensitive : api)("POST", `/owner/mcp/${p.name}/tools/${encodeURIComponent(short)}`, { allowed: mode === "auto" });
    rebuildCard(p.name);
  }, t.title);
  control.classList.add("compact");
  return h("div", { class: "tool-row compact", "data-find": `${t.title} ${t.name} ${t.description}`.toLowerCase() },
    h("div", { class: "grow" }, open), control);
}

// What changed in the server's tool list since the owner last looked, until they say they saw it.
function mcpNews(p) {
  const news = p.mcp.news;
  if (!news) return null;
  const titleOf = (name) => (p.mcp.tools.find((t) => t.name === name) || {}).title || name;
  const line = (label, names) => names.length ? h("p", {}, h("strong", {}, `${label}: `), names.map(titleOf).join(", ")) : null;
  const auto = p.mcp.tools.filter((t) => t.changed && t.allowed && t.kind === "write").map((t) => t.title);
  const hint = [news.new.length ? "New tools ask you first." : null,
    auto.length ? `${auto.join(", ")} still ${auto.length === 1 ? "runs" : "run"} without asking you.` : null,
    news.changed.length ? "Tap a changed tool to see what changed." : null].filter(Boolean).join(" ");
  const seen = h("button", { class: "quiet", type: "button" }, icon("check", "sm"), "Got it");
  seen.onclick = () => act(seen, () => api("POST", `/owner/mcp/${p.name}/seen`), () => rebuildCard(p.name));
  return h("div", { class: "mcp-note" }, h("div", { class: "mcp-news", role: "status" },
    h("p", { class: "news-head" }, "The server changed its tools", news.since ? h("span", { class: "meta" }, relative(news.since)) : null),
    line("New", news.new), line("Changed", news.changed), line("Gone", news.removed),
    hint ? h("p", { class: "meta" }, hint) : null,
    h("div", { class: "news-foot" }, seen)));
}

function mcpTools(p, set) {
  const mcp = p.mcp;
  const order = (a, b) => (b.new - a.new) || (!!b.changed - !!a.changed) || a.title.localeCompare(b.title);  // news first
  const reads = mcp.tools.filter((t) => t.kind === "read").sort(order);
  const writes = mcp.tools.filter((t) => t.kind === "write").sort(order);
  const count = (list) => {
    const fresh = list.filter((t) => t.new).length, changed = list.filter((t) => t.changed).length;
    return [String(list.length), fresh ? `${fresh} new` : null, changed ? `${changed} changed` : null].filter(Boolean).join(", ");
  };
  const group = (label, list, keep) => {
    const box = disclose(label, list.length ? list.map((t) => mcpToolRow(p, t, set)) : h("p", { class: "meta" }, "None."), { meta: count(list), keep });
    if (list.some((t) => t.new || t.changed)) box.open = true;  // what's new is on the screen without a tap
    return box;
  };
  const groups = [group("Reads · the agent uses these freely", reads, `reads:${p.name}`),
    group("Writes · ask you first unless set to Auto", writes, `writes:${p.name}`)];
  // long lists (a vendor's server has dozens of tools) get a filter over both groups
  const find = mcp.tools.length > 8 ? h("input", { type: "search", class: "tool-find", placeholder: `Find among ${mcp.tools.length} tools`,
    "aria-label": `Find a tool of ${mcp.title}`, autocomplete: "off", autocapitalize: "off", spellcheck: "false", "data-keep": `find:${p.name}` }) : null;
  const none = h("p", { class: "meta mt-2", hidden: true }, "No tool matches.");
  const filter = () => {
    const q = find.value.trim().toLowerCase();
    let found = 0;
    for (const box of groups) {
      let shown = 0;
      for (const row of box.querySelectorAll(".tool-row")) { row.hidden = !!q && !row.dataset.find.includes(q); shown += !row.hidden; }
      if (q) box.open = shown > 0;  // the matches are on the screen without a tap
      found += shown;
    }
    none.hidden = !q || found > 0;
  };
  if (find) { find.addEventListener("input", filter); setTimeout(filter); }  // a rebuilt card gets its filter back first
  const refresh = h("button", { class: "quiet", type: "button", "aria-label": "Check for new tools now" }, icon("retry", "sm"), "Check now");
  refresh.onclick = () => act(refresh, () => api("POST", `/owner/mcp/${p.name}/sync`), (out) => {
    const said = [out.added.length ? plural(out.added.length, "new tool", "new tools") : null,
      out.changed.length ? `${out.changed.length} changed` : null, out.removed.length ? `${out.removed.length} gone` : null].filter(Boolean);
    toast(said.length ? said.join(", ") : "Nothing changed");
    rebuildCard(p.name);
  });
  const signIn = mcp.auth === "oauth";  // the sign-in box above says it already
  return [
    mcp.error && !signIn ? h("div", { class: "mcp-note" }, warnRow(`Couldn't reach the server: ${mcp.error}`, "danger")) : null,
    mcpNews(p),
    mcp.tools.length ? [
      writes.length ? h("div", { class: "mcp-note" }, readOnlySwitch(p)) : null,
      h("div", { class: "mcp-note" }, find, find ? none : null, h("p", { class: "meta legend" }, MCP_LEGEND)),
      groups,
    ] : !signIn ? h("p", { class: "mcp-note meta" }, "No tools listed yet.") : null,
    h("div", { class: "mcp-foot" }, h("span", { class: "meta" }, mcp.synced ? `Tools checked ${relative(mcp.synced)}` : "Tools not checked yet"), refresh),
  ];
}
const MCP_LEGEND = "Off: the agent can't use it. Ask: every call waits for your OK. Auto: it runs without asking you. Tap a tool for more.";

// Names people know for plugin types, and plain words for the credentials they need.
const PLUGIN_TITLES = { notes: "Notes", nextcloud_notes: "Nextcloud Notes", google_calendar: "Google Calendar",
  caldav: "Calendar and tasks (CalDAV)", ics: "Calendar feed", mail_imap: "Mail (IMAP)",
  mail_outlook: "Outlook mail", files: "Files", whatsapp: "WhatsApp",
  teams: "Microsoft Teams", mcp: "MCP server" };
const pluginTitle = (type) => PLUGIN_TITLES[type] || (type.charAt(0).toUpperCase() + type.slice(1)).replace(/_/g, " ");
const CREDENTIAL_WORDS = { client_secret: "its client secret", refresh_token: "a sign-in", username: "your username",
  password: "your password", sidecar_token: "the WhatsApp sidecar token", login: "your login", pin: "your PIN",
  nextcloud_password: "your Nextcloud password", totp_secret: "your authenticator secret",
  url: "its address", token: "a token" };
// A setting's or credential's key in words for its label ("imap_host": "IMAP host"); the key itself
// follows as a small mono hint, since doorman.yaml and the plugin docs use it.
const KEY_WORDS = { id: "ID", url: "address", uri: "URI", imap: "IMAP", smtp: "SMTP", ocr: "OCR", iban: "IBAN",
  blz: "bank code (BLZ)", tan: "TAN", totp: "authenticator", pin: "PIN" };
function keyWords(key) {
  const text = String(key).split("_").map((w) => KEY_WORDS[w] || w).join(" ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}
const CREDENTIAL_LABELS = { client_secret: "Client secret", refresh_token: "Sign-in", totp_secret: "Authenticator secret",
  sidecar_token: "WhatsApp sidecar token", url: "Feed address" };
const credentialWords = (key) => CREDENTIAL_LABELS[key] || keyWords(key);
const keyHint = (key) => h("span", { class: "key-hint mono" }, key);

function needsText(keys) {
  const words = keys.map((k) => CREDENTIAL_WORDS[k] || k.replace(/_/g, " "));
  return `Needs ${words.length > 1 ? `${words.slice(0, -1).join(", ")} and ${words[words.length - 1]}` : words[0]}`;
}

// The positions a tool can take, and in one line what each does. Reads answer the agent at once, so they
// can't wait for you: they're on or off.
const MODE_LABEL = { off: "Off", ask: "Ask me", auto: "Auto" };
const MODE_HINT = { off: "The agent can't use it", ask: "Every call waits for your OK", auto: "Runs without asking you" };
function modeOptions(kind) {
  if (kind === "read") return [["off", "Off", "The agent can't use it"], ["auto", "On", "The agent reads it freely"]];
  const modes = kind === "payment" ? ["off", "ask"] : ["off", "ask", "auto"];  // payments always ask
  return modes.map((m) => [m, MODE_LABEL[m], MODE_HINT[m]]);
}

// What the tool does in its current position, under its name.
function modeEffect(t, mode, p) {
  if (mode === "off") return "Off: the agent can't use it.";
  if (t.kind === "read") return "On: the agent reads it freely.";
  if (t.kind === "payment") return "Asks you every time. Payments always do. Can't be undone.";
  const undoable = t.kind === "reversible";
  if (mode === "ask") return undoable ? "Asks you first. Can be undone afterwards." : "Asks you first. Can't be undone.";
  if (!undoable) return "Goes out without asking you while every check passes. Can't be undone.";
  return t.can_send && !p.no_approval ? "Runs without asking you; undo it in the Journal. Invitations to others still ask you."
    : "Runs without asking you; undo it in the Journal.";
}

function toolRow(p, t) {
  const short = t.name.split(".").slice(1).join(".");
  const off = p.disabled_tools.includes(short) || (t.kind !== "read" && p.read_only);
  const current = off ? "off" : t.kind === "read" ? "auto" : t.approval || "ask";
  const effect = h("div", { class: "meta" });
  const say = (mode) => {
    const custom = t.kind !== "read" && mode !== "off" && t.default_approval && mode !== t.default_approval;
    fill(effect, [t.kind === "irreversible" && mode === "auto" ? icon("send", "sm") : null,
      modeEffect(t, mode, p), custom ? h("span", { class: "custom" }, " Your choice.") : null]);
    effect.classList.toggle("sends", t.kind === "irreversible" && mode === "auto");
  };
  say(current);
  const name = t.description || short;
  const control = modeControl(modeOptions(t.kind), current, async (mode) => {
    // letting a send go out unasked is the one move that needs a second look and a fresh passkey check
    if (mode === "auto" && t.kind === "irreversible" && t.default_approval !== "auto") {
      const ok = await confirmSheet("Run this without asking you?",
        h("div", {}, h("p", { class: "tool-about" }, name),
          h("p", { class: "mt-2" }, "The agent's calls to it go out right away while every check passes. A new recipient or a full daily limit still asks you."),
          h("p", { class: "meta mt-2" }, "Each one is in the journal. None can be undone. Set it back to Ask me here.")),
        "Run without asking");
      if (!ok) return false;
    }
    // the passkey comes up whenever a send would run unasked again, such as one that runs on its own
    // switched back on: the server says so ("reauth")
    await sensitive("POST", `/owner/plugins/${p.name}`, { tool: short, mode });
    // read-only starts or ends with this pick: the other rows and the shortcut change too
    const writes = p.tools.map((w) => w.name.split(".").slice(1).join("."));
    const wasReadOnly = p.read_only;
    if (mode === "off") p.disabled_tools.push(short); else p.disabled_tools = p.disabled_tools.filter((x) => x !== short);
    if (t.kind !== "read" && mode !== "off") p.read_only = false;
    if (writes.length && writes.every((w) => p.disabled_tools.includes(w))) p.read_only = true;
    if (p.read_only !== wasReadOnly) return void rebuildCard(p.name);
    t.approval = mode === "off" ? t.approval : mode;
    say(mode);
    refreshCard(p.name);
  }, name);
  return h("div", { class: "tool-row modal" }, h("div", { class: "grow" }, h("div", { class: "tname" }, name), effect), control);
}

const MODE_LEGEND = "Off: the agent can't use it. Ask me: every call waits for your OK. Auto: it runs without asking you. Reads are on or off.";

// Read-only is a shortcut over the rows below it, not a setting of its own: on, every write is Off.
// Switching one write back on ends it; the other writes stay Off.
function readOnlySwitch(p) {
  return toggle(p.read_only, "Read-only", (v) => sensitive("POST", `/owner/plugins/${p.name}`, { read_only: v }).then(() => rebuildCard(p.name)),
    { hint: p.read_only ? "Every write is Off. Reads still work. Switch a write on below to allow just that one."
      : "Turns every write Off. Reads still work." });
}

// background jobs (a mailbox's archive): one line each, from the last run. A failure can be dismissed:
// it stays hidden (and out of Needs attention) until the job works again.
function jobLines(p) {
  const lines = Object.entries(p.job_status || {}).map(([name, j]) => {
    const text = j.status && j.status.summary ? j.status.summary : `${name}: not run yet`;
    if (j.error && j.dismissed) return h("div", { class: "meta" }, `${name} keeps failing (dismissed)`);
    if (!j.error) return h("div", { class: "meta" }, `${text.charAt(0).toUpperCase()}${text.slice(1)}`);
    const dismiss = h("button", { class: "quiet plain", type: "button", "aria-label": `Dismiss the ${name} error` }, "Dismiss");
    dismiss.onclick = () => act(dismiss, () => api("POST", `/owner/plugins/${p.name}/jobs/${encodeURIComponent(name)}/dismiss`),
      () => refreshCard(p.name));
    const row = warnRow([h("span", { class: "warn-title" }, `${name.charAt(0).toUpperCase()}${name.slice(1)} failed`),
      h("span", { class: "warn-text" }, j.error)], "danger");
    row.classList.add("job-failed");
    row.append(dismiss);
    return row;
  });
  return h("div", { class: "states", "data-part": "jobs", hidden: !lines.length }, lines);
}

// The tags under a card's description: missing credentials, sends without asking, ... Read-only isn't one:
// it lives with the tools it switches off.
function cardStates(p) {
  const missing = p.missing_credentials.filter((c) => p.login !== "oauth" || c !== "refresh_token");
  const allowed = p.mcp ? (p.read_only ? 0 : p.mcp.tools.filter((t) => t.kind === "write" && t.allowed && !p.disabled_tools.includes(t.name)).length)
    : p.no_approval ? 0 : p.tools.filter((t) => t.tier === "irreversible" && t.approval === "auto" && t.enabled).length;
  const tags = [
    missing.length ? (p.enabled ? h("span", { class: "tag danger" }, icon("alert", "sm"), needsText(missing))
      : h("span", { class: "meta" }, `${needsText(missing)} before it can be switched on`)) : null,
    p.no_approval ? h("span", { class: "tag" }, "Sends without asking you") : null,
    p.set_up_by ? h("span", { class: "tag warn" }, icon("alert", "sm"), `Set up by your agent (${p.set_up_by}): check its settings before switching it on`) : null,
    allowed ? h("span", { class: "tag" }, `${plural(allowed, "tool runs", "tools run")} without asking you`) : null,
  ].filter(Boolean);
  return h("div", { class: "states", "data-part": "states", hidden: !tags.length }, tags);
}

// Switches on a card change only that card: a tool switch updates its tags, switching the plugin on or off
// rebuilds the card.
const setPlugin = (name, body) => sensitive("POST", `/owner/plugins/${name}`, body)
  .then(() => ("enabled" in body ? rebuildCard(name) : refreshCard(name)));

function pluginCard(p, all) {
  const tools = [...p.reads.map((r) => ({ ...r, kind: "read" })), ...p.tools.map((t) => ({ ...t, kind: t.tier }))];
  const mcp = p.mcp;
  const title = mcp ? mcp.title : pluginTitle(p.type);
  const twin = all.filter((q) => (q.mcp ? q.mcp.title : q.type) === (mcp ? mcp.title : p.type)).length > 1;  // two of a kind: say which
  const set = setPlugin;
  return h("article", { class: "plugin", "aria-label": title, "data-plugin": p.name },
    h("div", { class: "plugin-head" }, tile(mcp ? { brand: mcp.icon, title } : { glyph: PLUGIN_GLYPHS[p.type] || "plugins" }),
      h("div", { class: "grow" }, h("h2", {}, title),
      mcp ? h("div", { class: "meta" }, `MCP server · ${mcp.host}${twin ? ` · called “${p.name}”` : ""}`)
        : twin ? h("div", { class: "meta" }, `Called “${p.name}”`) : null),
      toggle(p.enabled, null, (v) => set(p.name, { enabled: v }), { ariaLabel: `${title} on` })),
    h("p", { class: "desc" }, mcp ? "Reads run freely. Each write asks you first, unless you allow that tool. Doorman can't undo what a write does." : p.description),
    cardStates(p),
    p.enabled && p.login === "oauth" ? loginBox(p) : null,
    p.enabled && p.login === "link" ? linkBox(p) : null,
    p.enabled ? jobLines(p) : null,
    p.enabled ? h("div", { class: "rows" },
      settingsBox(p),
      mcp ? mcpTools(p, set) : disclose("Tools", [p.tools.length ? readOnlySwitch(p) : null,
        h("p", { class: "meta legend" }, MODE_LEGEND), tools.map((t) => toolRow(p, t))],
        { meta: `${p.read_only ? "Read-only · " : ""}${p.tools.length} tools, ${p.reads.length} reads`, keep: `tools:${p.name}` }))
      : h("div", { class: "rows" }, settingsBox(p)));
}

const cardOf = (name) => view.querySelector(`article.plugin[data-plugin="${CSS.escape(name)}"]`);

function pluginCount(plugins) {
  const sub = view.querySelector(".head .sub");
  if (sub) sub.textContent = `${plugins.filter((p) => p.enabled).length} of ${plugins.length} on`;
}

// After a change on a card: fetch the plugins again and update that card's tags, job lines and sign-in
// box, the credentials' Set/Missing, and settings fields you haven't edited. Nothing you typed is touched.
async function refreshCard(name) {
  try {
    const data = await api("GET", "/owner/plugins");
    const p = data.plugins.find((q) => q.name === name);
    const card = cardOf(name);
    if (!p || !card) return route();
    card.querySelector("[data-part=states]").replaceWith(cardStates(p));
    const jobs = card.querySelector("[data-part=jobs]");
    if (jobs && p.enabled) jobs.replaceWith(jobLines(p));
    const login = card.querySelector("[data-part=login]");
    // mid-connection (an address pasted, the sign-in link open) it stays as it is
    if (login && !login.dataset.busy && ![...login.querySelectorAll("input")].some((el) => el.value) && ![...login.querySelectorAll("a.button")].some((a) => !a.closest("[hidden]")))
      login.replaceWith(p.login === "link" ? linkBox(p) : loginBox(p));
    for (const el of card.querySelectorAll(`input[data-keep^="config:${CSS.escape(name)}:"]`)) {
      if (el.value !== el.defaultValue) continue;  // edited and not saved: yours
      el.defaultValue = shown((p.config || {})[el.dataset.keep.slice(`config:${name}:`.length)]);
      el.value = el.defaultValue;
    }
    pluginCount(data.plugins);
  } catch (err) { toast(err.message, "error"); }
}

// A change that reshapes a card (switched on or off, connected, new tools): build just that card again,
// keeping what you typed into it and which of its sections were open.
async function rebuildCard(name) {
  try {
    const data = await api("GET", "/owner/plugins");
    const p = data.plugins.find((q) => q.name === name);
    const card = cardOf(name);
    if (!p || !card) return route();
    const kept = keptState(card);
    const fresh = pluginCard(p, data.plugins);
    card.replaceWith(fresh);
    restoreState(fresh, kept);
    pluginCount(data.plugins);
  } catch (err) { toast(err.message, "error"); }
}

screens.plugins = async () => {
  const data = await api("GET", "/owner/plugins");
  const on = data.plugins.filter((p) => p.enabled).length;
  const cards = data.plugins.map((p) => pluginCard(p, data.plugins));
  const types = (data.available || []).filter((t) => t.type !== "mcp");  // MCP servers have their own row
  const fresh = types.filter((t) => !t.in_use);
  const again = types.filter((t) => t.in_use);
  const available = fresh.length || again.length
    ? section("Add a plugin", h("div", { class: "list" }, fresh.map(availableRow),
      again.length ? disclose("A second one of a kind you have", h("div", { class: "list nested" }, again.map(availableRow)),
        { meta: String(again.length), keep: "add:again" }) : null),
      { note: `Changes to plugins and credentials ask for your ${signIn}.` }) : null;
  // well-known servers that aren't connected yet, then any other by its address
  const hosts = new Set(data.plugins.filter((p) => p.mcp).map((p) => p.mcp.host));
  const names = new Set(data.plugins.map((p) => p.name));
  const known = (data.mcp_known || []).filter((k) => !hosts.has(new URL(k.url).hostname));
  const servers = section("Add an MCP server", h("div", { class: "list" }, known.map((k) => knownServerRow(k, names)), mcpAddRow()),
    { note: "A service's own server brings its tools into Doorman. Reads run freely; each write asks you first." });
  return [head("Plugins", `${on} of ${data.plugins.length} on`, stopButton()), cards, available, servers];
};

// ------------------------------------------------ more: push, trust, routines, passkeys, kill switch

function b64urlBytes(text) {
  const raw = atob(text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4));
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
}

// This device as the owner knows it, under More → Notifications and in the notice a new device sends to the
// others: "Chrome on Android". Anything it can't tell apart keeps the start of the user agent.
function deviceName() {
  const ua = navigator.userAgent;
  const os = /iPhone/.test(ua) ? "iPhone" : /iPad/.test(ua) ? "iPad" : /Android/.test(ua) ? "Android"
    : /Mac OS X/.test(ua) ? "Mac" : /Windows/.test(ua) ? "Windows" : /Linux/.test(ua) ? "Linux" : null;
  const browser = /Edg\//.test(ua) ? "Edge" : /SamsungBrowser/.test(ua) ? "Samsung Internet" : /Firefox\//.test(ua) ? "Firefox"
    : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : null;
  return os && browser ? `${browser} on ${os}` : ua.slice(0, 80);
}

// Subscribes this device for Doorman's key (afresh if it was made for another key or the push
// service dropped it) and tells Doorman. Doorman's side is an upsert, so repeating it is harmless.
async function subscribeDevice(registration, publicKey, fresh = false) {
  let subscription = await registration.pushManager.getSubscription();
  const key = b64urlBytes(publicKey);
  const current = subscription && subscription.options.applicationServerKey;
  if (subscription && (fresh || !current || new Uint8Array(current).join() !== key.join())) {
    await subscription.unsubscribe();
    subscription = null;
  }
  subscription = subscription || await registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key });
  try {
    return await api("POST", "/owner/push/subscribe", { subscription: subscription.toJSON(), label: deviceName() });
  } catch (err) {
    if (err.code === "push_gone" && !fresh) return subscribeDevice(registration, publicKey, true);
    throw err;
  }
}

async function enablePush(publicKey) {
  if (!pushSupported) throw new Error("This browser can't receive push notifications. On an iPhone, add the app to the Home Screen first.");
  if (await Notification.requestPermission() !== "granted") throw new Error("Notifications are blocked for this app in the browser settings.");
  await navigator.serviceWorker.register("sw.js");  // rejects with the real reason if the worker can't start
  return subscribeDevice(await navigator.serviceWorker.ready, publicKey);
}

// Once per app load, and again after each login: keep this device's subscription current without asking,
// so a rotated or dropped endpoint heals the next time the owner opens the app, and the subscription belongs
// to the login the device has now (logging out drops it, logging in again brings it back).
let pushSynced = false;
async function syncPush() {
  if (pushSynced || !pushSupported || Notification.permission !== "granted") return;
  pushSynced = true;
  const registration = await navigator.serviceWorker.getRegistration();
  const push = registration && await api("GET", "/owner/push");
  if (push && push.public_key) await subscribeDevice(registration, push.public_key);
}

// Removes one thing from a list. `ask` ([title, text, confirm label]) puts a confirm sheet first; `done`
// gets the answer and says what happened (a toast, maybe with Undo).
function removeButton(label, fn, { ask = null, done = null, aria = null } = {}) {
  const del = h("button", { class: "quiet plain", type: "button", "aria-label": aria }, label);
  del.onclick = async () => {
    if (ask && !(await confirmSheet(ask[0], ask[1], ask[2], "danger solid"))) return;
    act(del, fn, (out) => { if (done) done(out); route(); });
  };
  return del;
}

// ------------------------------------------------ agent keys and setup instructions

// A text block with a Copy button. Falls back to selecting the text where the clipboard API is missing.
function copyBlock(title, text) {
  const pre = h("pre", { class: "code", tabindex: "0" }, text);
  const label = h("span", {}, "Copy");
  const button = h("button", { class: "quiet", type: "button" }, icon("copy", "sm"), label);
  button.onclick = async () => {
    try {
      await navigator.clipboard.writeText(text);
      label.textContent = "Copied";
      setTimeout(() => { label.textContent = "Copy"; }, 2000);
    } catch (err) {
      getSelection().selectAllChildren(pre);
      toast("Couldn't copy automatically: the text is selected, copy it from there.", "error");
    }
  };
  return h("div", { class: "codeblock" }, h("div", { class: "codehead" }, h("span", {}, title), button), pre);
}

function agentSetup(url, token) {
  const dir = "~/.claude/skills/doorman";
  const fetch = [`mkdir -p ${dir}/scripts`,
    `curl -fsS -H "Authorization: Bearer ${token}" ${url}/v1/skill/SKILL.md -o ${dir}/SKILL.md`,
    `curl -fsS -H "Authorization: Bearer ${token}" ${url}/v1/skill/scripts/doorman.py -o ${dir}/scripts/doorman.py`].join("\n");
  const prompt = `Connect yourself to my Doorman. It holds my credentials; you reach my calendar, mail, notes and the rest only through it, with the doorman skill.

1. Install the skill:
${fetch}

2. Add these two variables to the "env" object in ~/.claude/settings.json (create the file if it doesn't exist and keep everything else in it):
DOORMAN_URL=${url}
DOORMAN_TOKEN=${token}

3. Check the connection:
DOORMAN_URL=${url} DOORMAN_TOKEN=${token} python3 ${dir}/scripts/doorman.py caps

Tell me which plugins it lists. The skill and the variables are loaded from your next session on.`;
  const shell = `${fetch}
export DOORMAN_URL=${url}
export DOORMAN_TOKEN=${token}
python3 ${dir}/scripts/doorman.py caps`;
  return [copyBlock("Message for Claude Code", prompt), copyBlock("Or run it yourself in the agent's shell", shell)];
}

const ROLE_INFO = {
  solo: ["Solo", "One agent does everything: reads, writes and sends (sends still wait for you). The usual choice."],
  reader: ["Reader", "For doorman-reader: turns mail, chats and new files into short records and answers the actor's questions. Can't change anything."],
  actor: ["Actor", "Changes and sends things, working from records and the reader's answers. Can't read raw third-party text."],
};

async function newKey(button, agentUrl) {
  const name = h("input", { id: "key-name", placeholder: "e.g. my-agent", autocapitalize: "off", spellcheck: "false" });
  const roles = Object.entries(ROLE_INFO).map(([role, [label, text]]) => h("label", { class: "choice" },
    h("input", { type: "radio", name: "key-role", value: role, checked: role === "solo" }),
    h("span", { class: "grow" }, h("span", { class: "primary-text" }, label), h("span", { class: "secondary-text" }, text))));
  // Solo is the normal setup; splitting reading from acting is optional hardening, so it waits behind Advanced
  const advanced = disclose("Advanced: split reading and acting", [
    h("p", { class: "meta mb-3" }, "Two agents instead of one: a reader that reads strangers' mail and chats but can't act, and an actor that acts but only sees the reader's records. Harder to set up; most people keep Solo."),
    h("div", { class: "field", role: "radiogroup", "aria-label": "Role" }, h("span", { class: "label" }, "Role"), roles)]);
  const go = await sheet({ title: "New agent key", actions: [{ label: "Create key", value: true, kind: "primary" }],
    body: [h("label", { class: "field" }, h("span", { class: "label" }, "Name"), name,
      h("span", { class: "hint" }, "Which agent or machine uses it. You can revoke each key on its own.")), advanced] });
  if (!go) return;
  const role = (roles.map((r) => r.querySelector("input")).find((r) => r.checked) || {}).value || "solo";
  act(button, () => sensitive("POST", "/owner/keys", { name: name.value, role }), async (out) => {
    await sheet({ title: `Key for ${out.key.name}`, cancel: "Done",
      body: [warnRow("The key is shown only now. Copy the setup before you close this."),
        out.key.role === "reader"
          ? [h("p", {}, "Put these lines in deploy/.env next to Doorman, fill in the model host, then run docker compose --profile reader up -d."),
            copyBlock("For deploy/.env", `READER_DOORMAN_TOKEN=${out.token}\nREADER_API_BASE=https://<model host>/v1\nREADER_API_KEY=<the host's API key>\nREADER_MODEL=<the host's model name>`)]
          : [h("p", {}, "Paste the message into Claude Code on the agent's machine, or run the commands there yourself."),
            agentSetup(out.agent_url || agentUrl, out.token)]] });
    route();
  });
}

function agentsSection(keys) {
  const active = keys.keys.filter((k) => !k.revoked);
  const revoked = keys.keys.length - active.length;
  const create = h("button", { class: "primary" }, icon("plus", "sm"), "New agent key");
  create.onclick = () => newKey(create, keys.agent_url);
  return section("Agents", h("div", { class: "list" },
    active.map((k) => {
      const revoke = h("button", { class: "quiet plain", type: "button", "aria-label": `Revoke ${k.name}` }, "Revoke");
      revoke.onclick = async () => {
        if (await confirmSheet(`Revoke “${k.name}”?`, "The agent using it loses access at once. Its journal stays.", "Revoke key", "danger solid"))
          act(revoke, () => api("POST", `/owner/keys/${k.id}/revoke`), () => { toast("Key revoked"); route(); });
      };
      // paused by a honeytoken: the agent can't do anything until the owner resumes it (fresh passkey)
      const resume = k.paused ? h("button", { class: "quiet plain", type: "button", "aria-label": `Resume ${k.name}` }, "Resume") : null;
      if (resume) resume.onclick = async () => {
        if (await confirmSheet(`Resume “${k.name}”?`, `It was paused: ${k.paused}. Resume it only if you know why the agent sent protected content.`, "Resume key"))
          act(resume, () => sensitive("POST", `/owner/keys/${k.id}/resume`), () => { toast("Key resumed"); route(); });
      };
      return h("div", { class: "row-item" }, icon("agent"), h("div", { class: "grow" },
        h("div", { class: "primary-text" }, k.name), h("div", { class: "secondary-text" }, `${(ROLE_INFO[k.role] || [k.role])[0]} · added ${when(k.created)}${k.paused ? " · paused (honeytoken)" : ""}`)), resume, revoke);
    }),
    active.length ? null : h("div", { class: "pad" }, h("p", { class: "muted small" }, "No agent can reach Doorman yet. Create a key, then paste the setup into your agent.")),
    disclose("Setup for an existing key", [h("p", { class: "meta mb-3" },
      "Keys are shown only when they're created. Replace <KEY> with the key, or create a new one."), agentSetup(keys.agent_url, "<KEY>")]),
    h("div", { class: "pad actions" }, create)),
    { count: active.length || undefined, note: revoked ? `Agents reach Doorman at ${keys.agent_url}. ${plural(revoked, "revoked key", "revoked keys")} not shown.` : `Agents reach Doorman at ${keys.agent_url}.` });
}

// ---------------------------------------------------------------- status

function stateRow(title, detail, state, extra) {
  // state: ["Working", "ok"] etc.; always words next to the dot, never color alone
  return h("div", { class: "row-item" }, h("div", { class: "grow" },
    h("div", { class: "primary-text" }, title),
    detail ? h("div", { class: "secondary-text" }, detail) : null, extra || null),
    state ? h("span", { class: `status ${state[1]}` }, state[0]) : null);
}

function weekLine(w) {
  const parts = [plural(w.actions, "action you can undo", "actions you can undo"), `${w.sent} sent`];
  if (w.reads) parts.push(plural(w.reads, "read", "reads"));
  if (w.denied) parts.push(`${w.denied} denied`);
  if (w.reverted) parts.push(`${w.reverted} reverted`);
  if (w.failed) parts.push(`${w.failed} failed`);
  return `Last 7 days: ${parts.join(", ")}.`;
}

function readerDetail(r) {
  if (!r) return "Hasn't reported a round yet";
  const round = `Last round ${relative(r.at)}`;
  if (r.failing_since) return `${round}: failing since ${when(r.failing_since)}${r.error ? ` (${r.error})` : ""}`;
  return `${round}: ${plural(r.recorded, "new record", "new records")}${r.failed ? `, ${r.failed} failed` : ""}`;
}

// The Backup row's line: the last good backup, whether it left this host, and the next nightly one.
function backupLine(b) {
  const where = b.copied === false ? ", but copying it off the host failed" : b.copied ? ", copied off the host"
    : b.last && !b.offsite ? ", on this host only" : "";
  const next = b.next ? `. Next ${when(b.next)}` : "";
  if (b.last) return `Last backup ${relative(b.last)}${where}${next}`;
  return b.next ? `None yet${next}` : "Set backup.dir in doorman.yaml and the worker makes one every night";
}

// The status in one line, the same on More and on Status. Paused is said first: it's the owner's own
// choice, not a fault, and "Everything is running" would be wrong while it lasts.
function statusHeadline(s) {
  const rows = [!s.worker.ok, s.backup.problem, s.tasks.problem, ...s.keys.map((k) => k.problem), ...s.plugins.map((p) => p.problem)];
  const problems = Math.max(s.attention || 0, rows.filter(Boolean).length);
  const paused = s.paused ? (s.keys.length ? "Agents are paused" : "Agents are stopped: every key was revoked") : null;
  const need = problems ? plural(problems, paused ? "other thing needs" : "thing needs", paused ? "other things need" : "things need") + " you" : null;
  return { text: paused && need ? `${paused}. ${need.charAt(0).toUpperCase()}${need.slice(1)}` : paused || (need ? need.charAt(0).toUpperCase() + need.slice(1) : "Everything is running"),
    problems, paused: !!paused };
}

screens.status = async () => {
  const s = await api("GET", "/owner/status");
  const w = s.week;
  const head_ = statusHeadline(s);
  const summary = `${head_.text}.${head_.paused ? " Resume under More." : ""}${head_.problems ? " Each problem is in your inbox too, until it's fixed." : ""}`;

  const doorman = section("Doorman", h("div", { class: "list" },
    stateRow("Worker", s.worker.seconds_ago == null ? "Starting" : `Looked for work ${Math.round(s.worker.seconds_ago)} s ago`,
      s.worker.ok ? ["Working", "ok"] : ["Stalled", "danger"]),
    stateRow("Agent access", !s.paused ? "Agents with a key can reach Doorman."
      : s.keys.length ? "Paused: every agent call is refused. The keys stay; resume under More."
        : "Stopped: every agent key was revoked. Resume and create a new key under More.",
      s.paused ? [s.keys.length ? "Paused" : "Stopped", "danger"] : ["Open", "ok"]),
    stateRow("Backup", backupLine(s.backup),
      s.backup.problem ? [s.backup.failed ? "Failed" : s.backup.last ? "Overdue" : "None yet", "warn"] : s.backup.last ? ["Recent", "ok"] : ["None yet", "quiet"]),
    stateRow("Tasks", s.tasks.problem ? `${s.tasks.problem}. Is the agent running?` : `${s.tasks.pending} waiting, ${s.tasks.claimed} in progress`,
      s.tasks.problem ? ["Not picked up", "warn"] : null)));

  const agents = section("Agents", h("div", { class: "list" },
    s.keys.length ? s.keys.map((k) => stateRow(k.name,
      k.role === "reader" ? readerDetail(k.reader) : k.last_used ? `${(ROLE_INFO[k.role] || [k.role])[0]} · last active ${relative(k.last_used)}` : `${(ROLE_INFO[k.role] || [k.role])[0]} · never used yet`,
      k.problem ? ["Not working", "warn"] : k.reader && k.reader.failing_since ? ["Failing", "warn"]
        : k.last_used ? ["Working", "ok"] : ["Never used", "quiet"],
      k.problem ? h("div", { class: "warns" }, warnRow(k.problem)) : null))
      : h("div", { class: "pad" }, h("p", { class: "muted small" }, "No agent keys. Create one under More."))),
    { note: "When each agent last reached Doorman. A reader reports every round it runs." });

  const plugins = section("Plugins", h("div", { class: "list" },
    s.plugins.length ? s.plugins.map((p) => stateRow(p.name,
      p.problem || (p.checked ? `Login checked ${relative(p.checked)}` : "Not checked yet"),
      p.problem ? ["Not working", "danger"] : p.checked ? ["Working", "ok"] : ["Waiting", "quiet"]))
      : h("div", { class: "pad" }, h("p", { class: "muted small" }, "No plugin is switched on."))));

  const week = section("Last 7 days", h("dl", { class: "list facts" },
    [["Actions you can undo", w.actions], ["Sent after your approval", w.sent], ["You approved", w.approved],
      ["You denied", w.denied], ["Expired unanswered", w.expired], ["Refused by Doorman", w.refused],
      ["Failed", w.failed], ["Reverted", w.reverted], ["Records from the reader", w.records],
      ["Records the reader left for you", w.records_review]]
      .filter(([label, n], i) => i < 2 || n)  // the first two always; the rest only when something happened
      .map(([label, n]) => h("div", {}, h("dt", {}, label), h("dd", { class: "num" }, String(n))))),
    { note: "Many denials or refusals mean the agent keeps asking for things you don't want. Many reader records for you mean it struggles with your mail." });

  return [topbar("Status", "#/more"), head("Status", summary), doorman, agents, plugins, week];
};

// ------------------------------------------------ more: trust list, routines and triggers

const TRUST_KINDS = [["email", "Email address", "anna@example.com"], ["phone", "Phone number", "+49 151 23456789"],
  ["iban", "Bank account (IBAN)", "DE89 3704 0044 0532 0130 00"], ["chat", "Chat", "Name or number of the chat"],
  ["url", "Web address", "https://example.com"]];
const trustKind = (k) => (TRUST_KINDS.find(([v]) => v === k) || [k, k])[1];

function trustSection(trust) {
  const kind = h("select", { "aria-label": "Kind" }, TRUST_KINDS.map(([k, words]) => h("option", { value: k }, words)));
  const value = h("input", { placeholder: TRUST_KINDS[0][2], "aria-label": "Address", autocapitalize: "off", spellcheck: "false", "data-keep": "trust:value" });
  kind.onchange = () => { value.placeholder = (TRUST_KINDS.find(([k]) => k === kind.value) || TRUST_KINDS[0])[2]; };
  const label = h("input", { placeholder: "Label (optional)", "aria-label": "Label", "data-keep": "trust:label" });
  const addTrust = h("button", { class: "primary" }, "Add to trust list");
  addTrust.onclick = () => act(addTrust, () => {
    if (!value.value.trim()) throw new Error("Type an address first.");
    return sensitive("POST", "/owner/trust", { kind: kind.value, value: value.value, label: label.value });
  }, (out) => { toast(`Added ${out.value || value.value.trim()} to your trust list`); value.value = ""; label.value = ""; route(); });
  // Who else counts as yours without being on the list. On by default; turning one on asks for the passkey.
  const known = trust.known || { contacts: true, written_before: true, locked: [] };
  const knownSwitch = (key, title, on, off) => {
    const fixed = (known.locked || []).includes(key);
    const row = toggle(known[key], title, async (want) => {
      await sensitive("POST", "/owner/trust/known", { [key]: want });
      toast(want ? on : off);
      route();
    }, { hint: fixed ? "Set in doorman.yaml." : known[key] ? on : off });
    if (fixed) row.querySelector("input").disabled = true;
    return h("div", { class: "pad" }, row);
  };
  return section("Trust list", h("div", { class: "list" },
    knownSwitch("contacts", "People in your contacts", "Sends to anyone in your own address books have no warning.",
      "Sends to people in your contacts warn unless they're on this list."),
    knownSwitch("written_before", "People you wrote to before", "Sends to anyone you approved a send to, or wrote to from your mail, have no warning.",
      "Sends to people you wrote to before warn unless they're on this list."),
    trust.trust.map((t) => h("div", { class: "row-item" }, h("div", { class: "grow" },
      h("div", { class: "primary-text" }, t.value), h("div", { class: "secondary-text" }, trustKind(t.kind), t.label ? ` · ${t.label}` : "")),
      removeButton("Remove", () => api("DELETE", `/owner/trust/${t.id}`), {
        aria: `Remove ${t.value}`,
        done: () => undoToast(`Removed ${t.value} from your trust list`,
          () => sensitive("POST", "/owner/trust", { kind: t.kind, value: t.value, label: t.label || "" })) }))),
    h("button", { class: "row-item row-button", type: "button", onclick: trustContact },
      icon("person"), h("span", { class: "grow" }, h("span", { class: "primary-text" }, "Trust a contact"),
        h("span", { class: "secondary-text" }, "Pick an address from your address book")), icon("chev", "sm")),
    h("div", { class: "pad" }, h("p", { class: "field-label" }, "Or type an address"), h("div", { class: "inline-form" }, kind, value),
      h("div", { class: "mt-2" }, label), h("div", { class: "mt-3" }, addTrust))),
    { note: "Approvals warn about recipients that aren't on this list, in your task or, with the switches on, in your contacts or written to before. Only you can change it.", count: trust.trust.length || undefined });
}

// "Trust a contact": the people in the owner's address books (GET /owner/contacts, any plugin whose manifest
// names a `contacts:` read). Tapping an address trusts it after the passkey check, like typing it in; the
// sheet closes and the toast offers Undo. The sheet covers the page, its offline banner and its toasts, so
// it says everything itself: no address book, one that couldn't be read, no match, no connection.
async function trustContact() {
  const picker = contactPicker();
  const picked = await sheet({ title: "Trust a contact", cls: "picker", cancel: "Close", body: picker.build });
  picker.stop();
  if (!picked) return;
  const out = picked.out;
  if (out.added && out.id) undoToast(`Added ${out.value} to your trust list`, () => api("DELETE", `/owner/trust/${out.id}`));
  else toast(`${out.value} was already on your trust list`, "info");
  route();
}

// A passkey prompt that was dismissed or timed out comes back as the browser's own words; say it plainly.
function passkeyWords(err) {
  return ["NotAllowedError", "AbortError"].includes(err && err.name)
    ? "The passkey check was cancelled or timed out. Nothing was added." : err.message;
}

const EMAIL_TYPES = { work: "Work", home: "Home", other: "Other", cell: "Mobile" };
const emailType = (t) => t.split(",").map((w) => EMAIL_TYPES[w] || w.charAt(0).toUpperCase() + w.slice(1)).join(", ");

function contactPicker() {
  const LIMIT = 50;
  const field = h("input", { type: "search", enterkeyhint: "search", placeholder: "Name, address or organisation",
    "aria-label": "Search your contacts", "aria-controls": "contact-results", autocomplete: "off", autocapitalize: "off",
    spellcheck: "false", "data-optional": "1" });  // on a phone the list shows first, not the keyboard
  const status = h("p", { class: "picker-status meta", role: "status" });
  const search = h("div", { class: "picker-search" }, icon("search", "sm"), field);
  const intro = h("p", {}, `Tap an address to add it to your trust list. Doorman asks for your ${signIn} first.`);
  const results = h("div", { id: "contact-results", class: "picker-results" });
  let finish = null, run = 0, timer = null, wasOffline = false, busy = false;
  // The status line announces each new result to a screen reader; it is seen only above a list.
  const say = (text, unseen = false) => { status.textContent = text; status.classList.toggle("sr-only", unseen); };

  const state = (mark, title, text, action, danger = false) => {
    say(title, true);  // announced; the block below shows it
    return h("div", { class: danger ? "problem compact" : "empty compact" },
      h("div", { class: "mark" }, icon(mark, "lg")), h("h3", {}, title), h("p", {}, text),
      action ? h("div", { class: "state-action" }, action) : null);
  };
  const retry = () => h("button", { type: "button", class: "primary", onclick: () => load() }, icon("retry", "sm"), "Try again");
  const toPlugins = (label) => h("a", { class: "button primary", href: "#/plugins", onclick: () => finish(null) }, label);

  // No source: say whether there's a contacts plugin to switch on, or one to add.
  async function noBook() {
    const plugins = await api("GET", "/owner/plugins").then((d) => d.plugins).catch(() => []);
    const mine = plugins.find((p) => p.type === "contacts");
    const typeIt = " Until then, type the address on the trust list.";
    if (!mine) return state("person", "No address book connected",
      `Add Contacts under Plugins to pick people from your Nextcloud address book.${typeIt}`, toPlugins("Go to Plugins"));
    if (!mine.enabled) return state("person", "Your contacts are switched off",
      `Switch on ${pluginTitle(mine.name)} under Plugins to pick people from it.${typeIt}`, toPlugins("Go to Plugins"));
    return state("person", "Searching contacts is switched off",
      `${pluginTitle(mine.name)} is on, but its search isn't. Switch it on under Plugins.${typeIt}`, toPlugins("Go to Plugins"));
  }

  function addressRow(person, e, first) {
    const kind = e.type ? emailType(e.type) : "";
    const text = [first ? h("span", { class: "primary-text" }, person.name) : null,
      h("span", { class: first ? "secondary-text" : "address-text" }, e.address, kind ? h("span", { class: "muted" }, ` · ${kind}`) : null),
      first && person.organisation ? h("span", { class: "meta" }, person.organisation) : null];
    const lead = first ? avatar(person.name) : h("span", { class: "avatar-space", "aria-hidden": "true" });
    if (e.trusted) return h("div", { class: "row-item contact-row" }, lead, h("span", { class: "grow" }, text),
      h("span", { class: "tag ok" }, icon("check", "sm"), "Trusted"));
    const row = h("button", { class: "row-item row-button contact-row", type: "button", "data-needs-net": "1", disabled: offline,
      "aria-label": `Trust ${person.name}, ${e.address}${kind ? `, ${kind}` : ""}` },
      lead, h("span", { class: "grow" }, text), h("span", { class: "go" }, "Trust"));
    row.onclick = () => pick(row, person, e);
    return row;
  }

  // One person: one row when they have one address; else their name, then a row per address under it.
  function personRows(person) {
    if (person.emails.length === 1) return addressRow(person, person.emails[0], true);
    return h("div", { class: "contact-group", role: "group", "aria-label": person.name },
      h("div", { class: "row-item contact-row" }, avatar(person.name), h("span", { class: "grow" },
        h("span", { class: "primary-text" }, person.name),
        person.organisation ? h("span", { class: "meta" }, person.organisation) : null)),
      person.emails.map((e) => addressRow(person, e, false)));
  }

  async function show(data, q) {
    const sources = Object.entries(data.sources || {});
    const broken = sources.filter(([, s]) => s.error);
    const people = data.contacts || [];
    search.hidden = intro.hidden = !sources.length;  // nothing to search or tap
    if (!sources.length) return [await noBook()];
    const why = broken.map(([name, s]) => `${pluginTitle(name)}: ${sentence(s.error)}`).join(" ");
    if (!people.length && broken.length === sources.length)
      return [state("alert", "Couldn't read your address book", `${why} You can still type the address on the trust list.`, retry(), true)];
    const partly = broken.length ? warnRow([h("span", { class: "warn-title" }, "Some contacts couldn't be read"),
      h("span", { class: "warn-text" }, why)]) : null;
    if (!people.length) return [partly, q
      ? state("search", `No one matches “${q}”`, "Only people with an email address are listed. Try part of a name, or type the address on the trust list.")
      : state("person", "No one with an email address yet", "People from your address book show here once they have an email address.")];
    say(`${plural(people.length, "person", "people")}${data.more ? `, the first ${LIMIT}` : ""}`);
    return [partly, h("div", { class: "list contacts" }, people.map(personRows)),
      data.more ? h("p", { class: "meta picker-more" }, `Showing the first ${LIMIT}. Search to find someone else.`) : null];
  }

  async function load() {
    const mine = ++run;
    const q = field.value.trim();
    clearTimeout(timer);
    const slow = setTimeout(() => {
      if (mine === run) results.replaceChildren(h("div", { class: "list contacts skeleton", "aria-hidden": "true" },
        [1, 2, 3].map(() => h("div", { class: "row-item contact-row" }, h("span", { class: "avatar" }), h("span", { class: "grow" },
          h("span", { class: "bar" }), h("span", { class: "bar short" }))))));
    }, 150);
    let parts;
    try {
      const data = await api("GET", `/owner/contacts?limit=${LIMIT}&q=${encodeURIComponent(q)}`);
      if (mine !== run) return;
      wasOffline = false;
      say("", true);
      parts = await show(data, q);
    } catch (err) {
      if (err.code === "signed_out") return finish(null);  // the login screen says why
      if (mine !== run) return;
      wasOffline = err.code === "offline";
      parts = [wasOffline
        ? state("alert", "No connection to Doorman", "Nothing was changed. The list comes back once you're online.", retry(), true)
        : state("alert", "Couldn't load your contacts", err.message, retry(), true)];
    } finally { clearTimeout(slow); }
    if (mine !== run) return;
    results.replaceChildren(...parts.filter(Boolean));
  }

  async function pick(row, person, e) {
    if (busy) return;
    busy = true;
    for (const old of results.querySelectorAll(".row-note")) old.remove();
    const rows = [...results.querySelectorAll("button.contact-row")];
    for (const b of rows) b.disabled = true;
    row.setAttribute("aria-busy", "true");
    try {
      const out = await sensitive("POST", "/owner/trust", { kind: "email", value: e.address, label: person.name });
      finish({ out, person });
    } catch (err) {
      if (err.code === "signed_out") return finish(null);
      row.after(h("div", { class: "row-note", role: "alert" }, warnRow(passkeyWords(err), "danger")));  // where the eye is
      for (const b of rows) b.disabled = offline;
      row.focus();
    } finally { busy = false; row.removeAttribute("aria-busy"); }
  }

  // Back online with the offline state showing: fetch the list again by itself.
  const online = () => { if (wasOffline) load(); };
  return {
    build(done) {
      finish = done;
      field.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(load, 250); });
      field.addEventListener("keydown", (ev) => { if (ev.key === "Enter") { ev.preventDefault(); load(); } });
      window.addEventListener("online", online);
      load();
      return [intro, search, status, results];
    },
    stop() { clearTimeout(timer); run++; window.removeEventListener("online", online); },
  };
}

// A schedule picked with chips and a time instead of typed as cron. Custom keeps cron for the shapes the
// chips don't cover.
const WEEKDAYS = [["1", "Monday"], ["2", "Tuesday"], ["3", "Wednesday"], ["4", "Thursday"], ["5", "Friday"], ["6", "Saturday"], ["0", "Sunday"]];
function schedulePicker() {
  const SHAPES = [["daily", "Every day", "*"], ["weekdays", "Weekdays", "1-5"], ["weekends", "Weekends", "0,6"], ["day", "One day", null], ["custom", "Custom", null]];
  let shape = "weekdays";
  const time = h("input", { type: "time", value: "07:30", "aria-label": "Time", required: true });
  const weekday = h("select", { "aria-label": "Day" }, WEEKDAYS.map(([v, words]) => h("option", { value: v }, words)));
  const cron = h("input", { placeholder: "30 7 * * 1-5", class: "mono", autocapitalize: "off", spellcheck: "false", "aria-label": "Schedule in cron form" });
  const dayRow = h("div", { class: "field", hidden: true }, h("span", { class: "label" }, "Day"), weekday);
  const timeRow = h("label", { class: "field" }, h("span", { class: "label" }, "Time"), time);
  const cronRow = h("label", { class: "field", hidden: true }, h("span", { class: "label" }, "Schedule in cron form"), cron,
    h("span", { class: "hint" }, "Minute, hour, day of the month, month, weekday. 30 7 * * 1-5 is weekdays at 07:30."));
  const chips = h("div", { class: "chips", role: "radiogroup", "aria-label": "How often" }, SHAPES.map(([v, words]) => {
    const input = h("input", { type: "radio", name: "routine-shape", value: v, checked: v === shape });
    input.onchange = () => { shape = v; dayRow.hidden = v !== "day"; timeRow.hidden = v === "custom"; cronRow.hidden = v !== "custom"; };
    return h("label", { class: "chip-choice" }, input, h("span", {}, icon("check", "sm"), words));
  }));
  const read = () => {
    if (shape === "custom") {
      if (!cron.value.trim()) throw new Error("Type the schedule first, or pick one of the choices above it.");
      return cron.value.trim();
    }
    const [hh, mm] = (time.value || "").split(":").map(Number);
    if (Number.isNaN(hh) || Number.isNaN(mm)) throw new Error("Pick a time first.");
    const days = shape === "day" ? weekday.value : SHAPES.find(([v]) => v === shape)[2];
    return `${mm} ${hh} * * ${days}`;
  };
  const rows = [h("div", { class: "field" }, h("span", { class: "label", id: "shape-label" }, "How often"), chips), dayRow, timeRow, cronRow];
  return { rows, read };
}

// What a plugin's event is, in a few words: "When a new mail arrives in mail".
const EVENT_WORDS = { new_mail: "a new mail arrives", new_message: "someone writes to you", invite_received: "someone invites you",
  event_soon: "an appointment is about to start", new_file: "a file arrives or changes" };
const eventWords = (event) => EVENT_WORDS[event] || String(event).replace(/_/g, " ");
function triggerLine(t) {
  let match = {};
  try { match = JSON.parse(t.match || "{}") || {}; } catch (_) { /* shown without the filter */ }
  const only = Object.entries(match).map(([k, v]) => (k === "from_trusted" ? "only from your trust list"
    : k === "from" ? `only from ${v}` : `only where ${k.replace(/_/g, " ")} is ${v}`));
  return `When ${eventWords(t.event)} in ${t.plugin}${only.length ? `, ${only.join(", ")}` : ""}`;
}

function routineRow(r) {
  const on = toggle(!!r.enabled, null, async (enabled) => {
    await sensitive("POST", `/owner/routines/${r.id}`, { enabled });
    toast(enabled ? `Routine “${r.name}” is on` : `Routine “${r.name}” is off: it makes no tasks until you switch it on`);
    route();
  }, { ariaLabel: `Routine ${r.name} on` });
  const del = removeButton("Delete", () => api("DELETE", `/owner/routines/${r.id}`), {
    aria: `Delete routine ${r.name}`,
    ask: [`Delete the routine “${r.name}”?`, "It makes no more tasks. Tasks it already made stay.", "Delete routine"],
    done: () => undoToast(`Routine “${r.name}” deleted`, async () => {
      const back = await sensitive("POST", "/owner/routines", { name: r.name, cron: r.cron, task_text: r.task_text });
      if (!r.enabled) await sensitive("POST", `/owner/routines/${back.id}`, { enabled: false });
    }) });
  return h("div", { class: "row-item routine" }, h("div", { class: "grow" },
    h("div", { class: "primary-text" }, r.name), h("div", { class: "secondary-text" }, cronText(r.cron), r.enabled ? "" : " · off"),
    h("div", { class: "secondary-text clamp" }, r.task_text), h("div", { class: "quiet-row tight" }, del)), on);
}

function triggerRow(t) {
  const del = removeButton("Delete", () => api("DELETE", `/owner/triggers/${t.id}`), {
    aria: `Delete trigger ${t.name}`,
    ask: [`Delete the trigger “${t.name}”?`, "It makes no more tasks. Tasks it already made stay.", "Delete trigger"],
    done: () => undoToast(`Trigger “${t.name}” deleted`, () => sensitive("POST", "/owner/triggers", {
      name: t.name, plugin: t.plugin, event: t.event, task_text: t.task_text, match: JSON.parse(t.match || "{}") })) });
  return h("div", { class: "row-item" }, h("div", { class: "grow" },
    h("div", { class: "primary-text" }, t.name), h("div", { class: "secondary-text" }, triggerLine(t)),
    h("div", { class: "secondary-text clamp" }, t.task_text), h("div", { class: "quiet-row tight" }, del)));
}

function addRoutineForm() {
  const name = h("input", { placeholder: "Morning brief", "data-keep": "routine:name" });
  const schedule = schedulePicker();
  const text = h("textarea", { placeholder: "What the agent should do each time", "data-keep": "routine:text" });
  const add = h("button", { class: "primary block" }, icon("plus", "sm"), "Add routine");
  const form = disclose("Add a routine", [
    h("label", { class: "field" }, h("span", { class: "label" }, "Name"), name), schedule.rows,
    h("label", { class: "field" }, h("span", { class: "label" }, "Task"), text,
      h("span", { class: "hint" }, "Your words, so the agent treats them as yours. What it may do is set in each plugin's Tools.")),
    add], { keep: "add:routine" });
  add.onclick = () => act(add, () => {
    if (!name.value.trim()) throw new Error("Give the routine a name first.");
    if (!text.value.trim()) throw new Error("Write what the agent should do first.");
    const cron = schedule.read();
    return sensitive("POST", "/owner/routines", { name: name.value.trim(), cron, task_text: text.value.trim() }).then(() => cron);
  }, (cron) => { toast(`Routine “${name.value.trim()}” added: ${cronText(cron).replace(/^./, (c) => c.toLowerCase())}`); forget(form); route(); });
  return form;
}

// A trigger turns an event a plugin reports (a new mail, an invitation) into a task. Its text is filled in
// from the event, so from what a stranger wrote: such tasks are marked "not written by you".
function addTriggerForm(plugins) {
  const sources = plugins.filter((p) => p.enabled && (p.events || []).length)
    .flatMap((p) => p.events.map((e) => ({ plugin: p.name, title: p.mcp ? p.mcp.title : pluginTitle(p.type), event: e })));
  if (!sources.length) return h("p", { class: "meta pad" }, "No switched-on plugin reports events yet, so there's nothing a trigger could start from.");
  const name = h("input", { placeholder: "Mail from the university", "data-keep": "trigger:name" });
  const when = h("select", { "aria-label": "When" }, sources.map((s, i) => h("option", { value: String(i) },
    `${s.title}${s.title.toLowerCase() === s.plugin ? "" : ` (${s.plugin})`}: ${eventWords(s.event.name)}`)));
  const from = h("input", { placeholder: "e.g. *@example.org", autocapitalize: "off", spellcheck: "false", "data-keep": "trigger:from" });
  const fromRow = h("label", { class: "field" }, h("span", { class: "label" }, "Only from (optional)"), from,
    h("span", { class: "hint" }, "An address or name. * stands for anything, so *@example.org is everyone at example.org."));
  const text = h("textarea", { placeholder: "Sort this mail and tell me if it needs an answer: {subject}", "data-keep": "trigger:text" });
  const fieldsHint = h("span", { class: "hint" });
  const sync = () => {
    const s = sources[Number(when.value)];
    const fields = s.event.fields || [];
    fromRow.hidden = !fields.includes("from");
    fieldsHint.textContent = fields.length ? `Words in braces are filled in from the event: ${fields.map((f) => `{${f}}`).join(", ")}.` : "";
  };
  when.onchange = sync;
  sync();
  const add = h("button", { class: "primary block" }, icon("plus", "sm"), "Add trigger");
  const form = disclose("Add a trigger", [
    h("p", { class: "meta" }, "A trigger gives the agent a task when something happens. Its tasks are marked “not written by you”: they are filled in from what someone else wrote, so addresses in them aren't trusted and every send still waits for you."),
    h("label", { class: "field" }, h("span", { class: "label" }, "Name"), name),
    h("label", { class: "field" }, h("span", { class: "label" }, "When"), when), fromRow,
    h("label", { class: "field" }, h("span", { class: "label" }, "Task"), text, fieldsHint),
    add], { keep: "add:trigger" });
  add.onclick = () => act(add, () => {
    if (!name.value.trim()) throw new Error("Give the trigger a name first.");
    if (!text.value.trim()) throw new Error("Write what the agent should do first.");
    const s = sources[Number(when.value)];
    const match = !fromRow.hidden && from.value.trim() ? { from: from.value.trim() } : {};
    return sensitive("POST", "/owner/triggers", { name: name.value.trim(), plugin: s.plugin, event: s.event.name, match, task_text: text.value.trim() });
  }, () => { toast(`Trigger “${name.value.trim()}” added`); forget(form); route(); });
  return form;
}

function routinesSection(routines, plugins) {
  const none = !routines.routines.length && !routines.triggers.length;
  return section("Routines and triggers", h("div", { class: "list" },
    routines.routines.map(routineRow), routines.triggers.map(triggerRow),
    none ? h("div", { class: "pad" }, h("p", { class: "muted small" }, "A routine gives the agent a task on a schedule; a trigger gives it one when something happens, like a new mail.")) : null,
    addRoutineForm(), plugins ? addTriggerForm(plugins.plugins) : null));
}

screens.more = async () => {
  const [settings, trust, routines, keys, push, agentKeys] = await Promise.all([api("GET", "/owner/settings"), api("GET", "/owner/trust"),
    api("GET", "/owner/routines"), api("GET", "/owner/passkeys"),
    api("GET", "/owner/push").catch((err) => ({ error: err.message, public_key: null, subject_ok: true, subscriptions: [] })),
    api("GET", "/owner/keys")]);
  const status = await api("GET", "/owner/status").catch(() => null);
  const guard = await api("GET", "/owner/guard").catch(() => null);
  const semantic = await api("GET", "/owner/semantic").catch(() => null);
  const plugins = await api("GET", "/owner/plugins").catch(() => null);  // the events a trigger can start from
  const egress = await api("GET", "/owner/egress").catch(() => null);

  // status
  const statusRow = section("Status", h("div", { class: "list" },
    h("a", { class: "row-item link-row", href: "#/status" }, icon(!status ? "check" : status.paused ? "power" : statusHeadline(status).problems ? "warn" : "check"),
      h("div", { class: "grow" }, h("div", { class: "primary-text" }, status ? statusHeadline(status).text : "Status"),
        h("div", { class: "secondary-text" }, status ? weekLine(status.week) : "Agents, plugins, backups and the last 7 days")),
      icon("chev"))));

  // notifications
  const enable = h("button", { class: "primary" }, icon("bell", "sm"), "Enable on this device");
  enable.onclick = () => act(enable, () => enablePush(push.public_key), () => { toast("Notifications on"); route(); });
  const testPush = h("button", {}, "Send a test");
  testPush.onclick = () => act(testPush, () => api("POST", "/owner/push/test"), (r) => {
    const failed = r.results.filter((x) => !x.ok);
    if (failed.length) toast(failed.map((x) => `${x.label || `Device ${x.id}`}: ${x.status ? `HTTP ${x.status}` : "unreachable"} ${x.reason}`).join("; "), "error");
    else toast(`Sent to ${plural(r.results.length, "device", "devices")}`);
    route();
  });
  const pushWarnings = [
    pushSupported ? null : warnRow(plainHttp ? "Notifications need an HTTPS address: browsers give none over plain HTTP. You see what waits when you open the app."
      : "This browser can't receive push notifications. On an iPhone, add the app to the Home Screen first (iOS 16.4 or later), then open it from there."),
    push.error ? warnRow(`Notifications can't be set up right now: ${push.error}`, "danger") : null,
    push.subject_ok ? null : warnRow("Set push.subject in doorman.yaml to mailto:you@example.com. Apple refuses pushes without a real contact."),
  ].filter(Boolean);
  const notifications = section("Notifications", h("div", { class: "list" },
    pushWarnings.length ? h("div", { class: "pad warns m-0" }, pushWarnings) : null,
    push.subscriptions.map((s) => h("div", { class: "row-item" }, h("div", { class: "grow" },
      h("div", { class: "primary-text" }, s.label || `Device ${s.id}`),
      h("div", { class: "secondary-text" }, s.last_ok ? `Last delivered ${when(s.last_ok)}` : `Added ${when(s.created)}`),
      s.failures ? h("div", { class: "warns" }, warnRow(`${plural(s.failures, "failed delivery", "failed deliveries")}: ${s.last_error || "unknown error"}. Open the app on that device and tap Enable again.`)) : null),
      removeButton("Remove", () => api("DELETE", `/owner/push/${s.id}`), {
        aria: `Remove ${s.label || `device ${s.id}`}`,
        ask: [`Stop notifications on ${s.label || "this device"}?`, "It gets no more pushes about sends that wait for you. To get them again, open the app there and tap Enable on this device.", "Remove device"],
        done: () => toast(`${s.label || "The device"} gets no more notifications`) }))),
    !push.subscriptions.length && !pushWarnings.length ? h("div", { class: "pad" }, h("p", { class: "muted small" }, "No device gets pushes yet. Without them you only see approvals when you open the app.")) : null,
    push.public_key || push.subscriptions.length ? h("div", { class: "pad actions" }, push.public_key ? enable : null, push.subscriptions.length ? testPush : null) : null));

  // limits (read-only facts from doorman.yaml)
  const facts = section("Limits", h("dl", { class: "list facts" },
    h("div", {}, h("dt", {}, "Approvals"), h("dd", {}, settings.approval_passkey ? "Passkey each time" : "A tap")),
    h("div", {}, h("dt", {}, "Without asking, at most a day"), h("dd", {}, settings.limits.direct_per_day ?? settings.limits.sends_per_day ?? 30)),
    h("div", {}, h("dt", {}, "Payments budget a month"), h("dd", {}, settings.payments.monthly_budget)),
    h("div", {}, h("dt", {}, "Second-opinion reviewer"), h("dd", {}, settings.reviewer ? "On" : "Off"))),
    { note: "Every email, message and invitation waits for your approval. Plugins you let run without asking ask again after the daily number. These are set in doorman.yaml." });

  // passkeys and session
  const addKey = h("button", {}, icon("plus", "sm"), "Add a passkey");
  addKey.onclick = async () => {
    const name = h("input", { value: "", placeholder: "e.g. Laptop" });
    const ok = await sheet({ title: "Add a passkey", actions: [{ label: "Create passkey", value: true, kind: "primary" }],
      body: [h("p", {}, "For another device or a security key. Each passkey can log in on its own."),
        h("label", { class: "field" }, h("span", { class: "label" }, "Name"), name)] });
    if (!ok) return;
    act(addKey, async () => {
      const start = await sensitive("POST", "/owner/auth/register/options", {});  // a recent passkey check first
      const credential = await navigator.credentials.create({ publicKey: creationOptions(start.options) });
      await api("POST", "/owner/auth/register/verify", { challenge_id: start.challenge_id, credential: credentialJSON(credential), label: name.value.trim() || "passkey" });
    }, () => { toast("Passkey added"); route(); });
  };
  const logout = h("button", {}, "Log out");
  logout.onclick = () => act(logout, () => api("POST", "/owner/auth/logout"), () => { location.hash = "#/login"; });
  const passkeys = section("Passkeys", h("div", { class: "list" },
    keys.passkeys.length ? keys.passkeys.map((k) => {
      let remove = null;
      if (keys.passkeys.length > 1) {
        remove = h("button", { class: "quiet", type: "button" }, "Remove");
        remove.onclick = async () => {
          const ok = await sheet({ title: `Remove ${k.label}?`, actions: [{ label: "Remove passkey", value: true, kind: "danger" }],
            body: [h("p", {}, "The device it's on is signed out right away and stops getting notifications. It can't log in or approve any more, not even from a notification it already has.")] });
          if (ok) act(remove, () => sensitive("POST", "/owner/passkeys/remove", { id: k.id }), (r) => {
            toast(r.signed_out ? "Passkey removed. This device is signed out." : "Passkey removed. Its device is signed out.");
            if (r.signed_out) location.hash = "#/login"; else route();
          });
        };
      }
      return h("div", { class: "row-item" }, icon("key"), h("div", { class: "grow" },
        h("div", { class: "primary-text" }, k.label),
        h("div", { class: "secondary-text" }, `Added ${when(k.created)}${k.here ? "" : ` on ${k.rp_id}, an old address: it can't log in here`}`)), remove);
    })
      : h("div", { class: "row-item" }, icon("key"), h("div", { class: "grow" }, h("div", { class: "primary-text" }, "No passkey yet"),
        h("div", { class: "secondary-text" }, "This session didn't log in with one. Add a passkey to log in on this device next time."))),
    h("div", { class: "pad actions" }, addKey, logout)));
  const passwordSection = section("Sign-in", h("div", { class: "list" },
    h("div", { class: "row-item" }, icon("key"), h("div", { class: "grow" },
      h("div", { class: "primary-text" }, "Password"),
      h("div", { class: "secondary-text" }, "Set on Doorman's host. To change it, run ", h("code", {}, "doorman-admin sign-in password"),
        " there. With an HTTPS address you can use a passkey instead: ", h("code", {}, "doorman-admin sign-in passkey"), "."))),
    plainHttp ? warnRow(PLAIN_HTTP) : null,
    h("div", { class: "pad actions" }, logout)));

  // emergency stop: Pause keeps the keys, Revoke all keys doesn't
  const keysLeft = settings.agent_keys > 0;
  const main = !settings.paused
    ? h("button", { class: "danger block", type: "button" }, icon("power", "sm"), "Pause agents")
    : h("button", { class: "primary block", type: "button" }, keysLeft ? "Resume agents" : "Resume and create a new key");
  main.onclick = () => {
    if (!settings.paused) return act(main, () => api("POST", "/owner/pause"),
      () => { toast("Paused. The keys stay; Resume brings the agent back."); route(); });
    // resuming gives access back to every key that still works: that asks for your passkey
    return act(main, () => sensitive("POST", "/owner/resume"), () => {
      if (keysLeft) { toast("Resumed. Agents with a key can call again."); route(); }
      else { toast("Resumed. No agent has a key yet: create one now."); route(); newKey(main, agentKeys.agent_url); }
    });
  };
  const revokeAll = keysLeft ? h("button", { class: "quiet danger", type: "button" }, "Revoke all keys") : null;
  if (revokeAll) revokeAll.onclick = () => revokeAllKeys(revokeAll);
  const danger = section("Emergency stop", h("div", { class: "list danger-zone" },
    h("div", { class: "pad" }, h("p", {}, !settings.paused
      ? "If the agent misbehaves: every agent call is refused at once. Waiting sends stay for you to decide, and the keys stay, so Resume brings the agent back."
      : keysLeft ? "Paused: every agent call is refused. The keys stay, so the agent is back as soon as you resume."
        : "Stopped: every agent key was revoked. Resuming alone brings no agent back: it needs a new key and its setup again."),
    main),
    revokeAll ? h("div", { class: "pad" }, h("p", {}, "If a key may have leaked: revoke every key. The agent then needs a new key, set up again from a computer."),
      h("div", { class: "quiet-row tight" }, revokeAll)) : null));

  const privacyRow = section("Privacy", h("div", { class: "list" },
    h("a", { class: "row-item link-row", href: "#/privacy" }, icon("shield"),
      h("div", { class: "grow" }, h("div", { class: "primary-text" }, "What agents don't see"),
        h("div", { class: "secondary-text" }, "Doctor's appointments and your own words become placeholders")),
      icon("chev")),
    h("a", { class: "row-item link-row", href: "#/guard" }, icon(!guard || ["ready", "off"].includes(guard.state) ? "shield" : "warn"),
      h("div", { class: "grow" }, h("div", { class: "primary-text" }, "Injection guard"),
        h("div", { class: "secondary-text" }, !guard ? "Scans third-party text before agents get it"
          : guard.held ? `${plural(guard.held, "item", "items")} held back for you to look at`
            : guard.state === "ready" ? "Scans mail, attachments, files and chats before agents get them"
              : guard.state === "off" ? "Off. Optional: scans third-party text before agents get it"
                : `${(GUARD_STATE[guard.state] || [guard.state])[0]}: nothing is scanned`)),
      guard && guard.state !== "ready" ? h("span", { class: `status ${(GUARD_STATE[guard.state] || ["", "quiet"])[1]}` }, (GUARD_STATE[guard.state] || [guard.state])[0]) : null,
      icon("chev")),
    h("a", { class: "row-item link-row", href: "#/network" }, icon(egress && egress.enabled && egress.status.seen && !egress.status.up ? "warn" : "globe"),
      h("div", { class: "grow" }, h("div", { class: "primary-text" }, "Network"),
        h("div", { class: "secondary-text" }, !egress ? "What the agent sends to the internet"
          : !egress.enabled ? "Not set up. The agent reaches the internet unwatched."
            : `${proxyLine(egress.status)} · today ${plural(egress.counts.today, "connection", "connections")}, ${egress.counts.blocked_today} blocked`)),
      egress && egress.enabled && !egress.status.up ? h("span", { class: `status ${proxyState(egress.status)[1]}` }, proxyState(egress.status)[0]) : null,
      icon("chev"))));

  const searchRow = section("Search", h("div", { class: "list" },
    h("a", { class: "row-item link-row", href: "#/semantic" }, icon("search"),
      h("div", { class: "grow" }, h("div", { class: "primary-text" }, "Semantic search"),
        h("div", { class: "secondary-text" }, !semantic || !semantic.enabled
          ? "Off. Search finds words, other forms of them and close spellings."
          : semantic.state === "ready" ? "On: search also finds things by what they mean, in any language"
            : `${(SEMANTIC_STATE[semantic.state] || [semantic.state])[0]}`)),
      semantic && semantic.enabled && semantic.state !== "ready"
        ? h("span", { class: `status ${(SEMANTIC_STATE[semantic.state] || ["", "quiet"])[1]}` }, (SEMANTIC_STATE[semantic.state] || [semantic.state])[0]) : null,
      icon("chev"))));

  return [head("More"), danger, statusRow, privacyRow, searchRow, agentsSection(agentKeys), notifications, trustSection(trust), routinesSection(routines, plugins), facts,
    settings.sign_in === "password" ? passwordSection : passkeys];
};

// ---------------------------------------------------------------- shell and router

const TABS = [["inbox", "Inbox"], ["journal", "Journal"], ["tasks", "Tasks"], ["plugins", "Plugins"], ["more", "More"]];
tabs.append(h("div", { class: "brand" }, h("img", { src: "icon.svg", alt: "" }), "Doorman"),
  ...TABS.map(([name, text]) => h("a", { href: `#/${name}`, "data-tab": name },
    h("span", { class: "pill" }, icon(name)), h("span", {}, text),
    name === "inbox" ? h("span", { class: "badge", hidden: true }) : null)));

let badgeCount = 0;
function setBadge(n) {
  const badge = tabs.querySelector(".badge");
  if (n && n !== badgeCount && !badge.hidden && !reducedMotion.matches)
    play(badge, [{ transform: "scale(1.3)" }, { transform: "none" }], { duration: 360 });
  badgeCount = n;
  badge.hidden = !n;
  badge.textContent = n > 99 ? "99+" : String(n);
  tabs.querySelector('[data-tab="inbox"]').setAttribute("aria-label", n ? `Inbox, ${n} waiting` : "Inbox");
  if (navigator.setAppBadge) (n ? navigator.setAppBadge(n) : navigator.clearAppBadge()).catch(() => {});
}

function refreshBadge() {
  api("GET", "/owner/inbox").then((d) => setBadge(inboxCount(d))).catch(() => {});
}

function skeleton() {
  return h("div", { class: "skeleton", "aria-hidden": "true" }, h("div", { class: "bar title" }),
    h("div", { class: "block" }), h("div", { class: "block" }), h("div", { class: "bar w-60" }));
}

function problem(err) {
  const retry = h("button", { class: "primary" }, icon("retry", "sm"), "Try again");
  retry.onclick = () => route();
  const away = err.code === "offline";
  return h("div", { class: "problem", role: "alert" }, h("div", { class: "mark" }, icon("alert", "lg")),
    h("h2", {}, away ? "No connection to Doorman" : "Couldn't load this"),
    h("p", {}, away ? "Nothing was sent or changed. This loads again once you're back online." : err.message), retry);
}

const PUBLIC_SCREENS = ["login"];  // reachable without an owner session
screens.privacy = async () => {
  const p = await api("GET", "/owner/privacy");
  const enabled = localSwitch(p.enabled, "Hide sensitive content from agents",
    "Agents and their model provider get placeholders like [Gesundheit PSN-3F2A9C1B]. You always see the real text here.");
  const words = h("textarea", { rows: 5, placeholder: "One per line, e.g.\nBewerbung\n*therapie*\nAnna Berg", autocapitalize: "off", spellcheck: "false" },
    p.extra_words.join("\n"));
  const save = h("button", { class: "primary" }, "Save");
  save.onclick = () => act(save, () => sensitive("POST", "/owner/privacy", {
    enabled: enabled.box.checked, extra_words: words.value.split("\n").map((w) => w.trim()).filter(Boolean) }),
    () => { toast("Saved"); route(); });

  const sample = h("input", { type: "text", value: "Termin - Herr Dr. med. Sondermann", autocomplete: "off", "aria-label": "Text to try" });
  const out = h("div", {});
  const tryIt = h("button", {}, "Show what the agent sees");
  tryIt.onclick = () => act(tryIt, () => api("POST", "/owner/privacy/preview", { text: sample.value }), (r) => out.replaceChildren(
    ...[["As a calendar title", r.as_title], ["In a mail", r.in_mail]].map(([label, text]) =>
      h("div", { class: "pad preview-line" }, h("div", { class: "meta" }, label), h("div", { class: "mono" }, text)))));

  const WHERE = { all: "Titles, places, senders and any sentence in a text", headers: "Titles, places and senders only" };
  const rules = section("Built-in rules", h("div", { class: "list" }, p.rules.map((r) => h("details", { class: "disclose" },
    h("summary", {}, h("span", { class: "grow" }, h("span", { class: "primary-text as-block" }, `${r.label}: ${plural(r.words.length, "word", "words")}`),
      h("span", { class: "meta as-block regular" }, WHERE[r.where] || r.where, r.plugins ? ` · ${r.plugins.join(", ")}` : "")), icon("chev", "sm chev")),
    h("div", { class: "content" }, h("p", { class: "mono small word-list" }, r.words.join(" · ")))))),
    { note: "A word in a title, place or sender hides the whole item: every text in it becomes a placeholder, times and ids stay, so the agent still knows the slot is taken. A word inside a mail body or description replaces just that sentence. *x* also matches inside words. Change these in doorman.yaml (pseudonymize.rules)." });

  return [topbar("Privacy", "#/more"),
    head("Privacy", `${plural(p.pseudonyms, "placeholder", "placeholders")} handed out so far. An agent can pass one back to move or keep that item; a message that contains one is refused, so hidden text can't be sent to anyone.`),
    section("For agents", h("div", { class: "list" }, h("div", { class: "pad" }, enabled.row),
      h("div", { class: "pad" }, h("label", { class: "field" }, h("span", { class: "label" }, "Your own words"), words,
        h("span", { class: "hint" }, "Hidden like the built-in ones, under the label Privat. Names, topics, anything.")),
        h("div", { class: "actions" }, save)))),
    section("Try it", h("div", { class: "list" }, h("div", { class: "pad" }, h("div", { class: "inline-form" }, sample), h("div", { class: "actions" }, tryIt)), out)),
    rules];
};

// ---------------------------------------------------------------- the injection guard

const GUARD_STATE = {
  ready: ["Scanning", "ok"], off: ["Off", "quiet"], missing: ["No model yet", "warn"],
  downloading: ["Downloading", "quiet"], broken: ["Not working", "danger"],
};
const QUARANTINE_STATE = { held: ["Held back", "warn"], kept: ["Kept back", "quiet"], released: ["Released", "ok"] };
const megabytes = (n) => `${Math.round(n / 1e6)} MB`;

function guardSummary(g) {
  if (!g.enabled) return `Off. Optional: a small model on your server checks mail, attachments, files and chats for text that tries to steer the agent, and holds back what scores high. Switching it on downloads the model (${megabytes(g.model.size)}); it takes about 800 MB of memory while it scans.`;
  if (g.state === "missing") return "On, but the model isn't downloaded yet, so nothing is scanned. Download it below.";
  if (g.state === "downloading") return "Downloading the model. Until it's there, nothing is scanned.";
  if (g.state === "broken") return "On, but the scanner isn't working, so text reaches agents unscanned.";
  return "Before an agent gets mail, an attachment, a file or a chat, a small model checks it for text that tries to steer the agent. What scores high is held back until you look at it.";
}

function quarantineRow(q) {
  const [label, cls] = QUARANTINE_STATE[q.status] || [q.status, "quiet"];
  return h("a", { class: "row-item link-row", href: `#/quarantine/${q.id}` }, h("div", { class: "grow" },
    h("div", { class: "primary-text" }, q.label || q.ref || "An item"),
    h("div", { class: "secondary-text" }, [q.source, q.sender, relative(q.created)].filter(Boolean).join(" · "))),
    h("span", { class: `status ${cls}` }, label), icon("chev"));
}

const SEMANTIC_STATE = {
  ready: ["On", "ok"], off: ["Off", "quiet"], missing: ["No model yet", "warn"],
  downloading: ["Downloading", "quiet"], broken: ["Not working", "danger"],
};

screens.semantic = async () => {
  const s = await api("GET", "/owner/semantic");
  const downloading = s.download.state === "downloading";
  if (downloading) setTimeout(() => { if ((location.hash || "").startsWith("#/semantic")) route(); }, 1500);
  const locked = (s.locked || []).includes("enabled");
  const enabled = toggle(s.enabled, "Find things by meaning", async (on) => {
    await api("POST", "/owner/semantic", { enabled: on });
    toast(on ? (s.model.ready ? "Semantic search on" : "Semantic search on; downloading the model") : "Semantic search off");
    route();
  }, { hint: locked ? "Set in doorman.yaml."
    : "Searching for “deposit” also finds “Kaution” and “borg”. Switching it on downloads the model once." });
  if (locked) enabled.querySelector("input").disabled = true;
  const retry = h("button", {}, "Try the download again");
  retry.onclick = () => act(retry, () => api("POST", "/owner/semantic/fetch"), () => route());
  const model = section("Model", h("div", { class: "list" },
    stateRow(s.model.name, `${megabytes(s.model.size)} · ${s.model.license} · ${s.running ? "running now" : "starts when needed"}`,
      SEMANTIC_STATE[s.state] || [s.state, "quiet"]),
    downloading ? h("div", { class: "pad" }, h("progress", { class: "guard-progress", max: s.download.total, value: s.download.done }),
      h("p", { class: "meta mt-1" }, `${megabytes(s.download.done)} of ${megabytes(s.download.total)}`)) : null,
    s.download.state === "failed" ? h("div", { class: "pad warns m-0" }, warnRow(s.download.error, "danger"), h("div", { class: "actions mt-1" }, retry)) : null,
    s.error && s.state === "broken" ? h("div", { class: "pad warns m-0" }, warnRow(s.error, "danger")) : null),
    { note: "It runs on your server, in a process of its own that stops when idle (about 500 MB while it runs). Nothing is sent anywhere." });
  const sources = s.sources.length ? section("Sources", h("div", { class: "list" }, s.sources.map((src) =>
    h("div", { class: "pad" }, h("div", { class: "primary-text" }, src.name),
      s.enabled ? h("progress", { class: "guard-progress", max: src.of || 1, value: src.embedded }) : null,
      h("p", { class: "meta mt-1" }, src.error ? `Last update failed: ${src.error}`
        : !src.pulled ? "Not in search yet"
        : `${src.items} ${src.items === 1 ? "item" : "items"}` + (s.enabled ? (src.embedded >= src.of ? ", all read for meaning" : `, ${src.embedded} of ${src.of} parts read for meaning, newest first`) : "")),
      src.skipped ? h("p", { class: "meta" }, `${src.skipped} ${src.skipped === 1 ? "item" : "items"} left out of search: ${src.skip_note}`) : null))),
    { note: "Doorman keeps one search index over everything below. With semantic search on, each text is read once in the background while no agent is searching." }) : null;
  return [topbar("Semantic search", "#/more"),
    head("Semantic search", s.enabled ? "Search finds words, other forms of them, close spellings, and text that means the same in other words or languages, in mail, files, notes, calendars and chats."
      : "Search finds words, other forms of them (Rechnungen, Rechnung) and close spellings, in mail, files, notes, calendars and chats. With semantic search it also finds things by meaning."),
    section("Settings", h("div", { class: "list" }, h("div", { class: "pad" }, enabled))), model, sources];
};

screens.guard = async () => {
  const [g, list] = await Promise.all([api("GET", "/owner/guard"), api("GET", "/owner/quarantine?limit=50")]);
  const locked = new Set(g.locked || []);

  const fetchButton = h("button", { class: "primary" }, g.download.state === "failed" ? "Try the download again" : `Download model (${megabytes(g.model.size)})`);
  fetchButton.onclick = () => act(fetchButton, () => api("POST", "/owner/guard/fetch"), () => route());
  const downloading = g.download.state === "downloading";
  if (downloading) setTimeout(() => { if ((location.hash || "").startsWith("#/guard")) route(); }, 1500);
  const scanner = section("Scanner", h("div", { class: "list" },
    stateRow(g.model.name, `${megabytes(g.model.size)} · ${g.model.license} · ${g.running ? "running now" : "starts on the next scan"}`,
      GUARD_STATE[g.state] || [g.state, "quiet"]),
    downloading ? h("div", { class: "pad" }, h("progress", { class: "guard-progress", max: g.download.total, value: g.download.done }),
      h("p", { class: "meta mt-1" }, `${megabytes(g.download.done)} of ${megabytes(g.download.total)}`)) : null,
    g.error && g.state === "broken" ? h("div", { class: "pad warns m-0" }, warnRow(g.error, "danger")) : null,
    g.download.state === "failed" ? h("div", { class: "pad warns m-0" }, warnRow(g.download.error, "danger")) : null,
    !g.model.ready && !downloading ? h("div", { class: "pad actions" }, fetchButton) : null),
    { note: "The model runs on your server, in a process of its own that stops when it isn't needed. Nothing is sent anywhere to be checked." });

  const enabled = toggle(g.enabled, "Scan third-party text", async (on) => {
    await sensitive("POST", "/owner/guard", { enabled: on });
    toast(on ? "Guard on" : "Guard off");
    route();
  }, { hint: locked.has("enabled") ? "Set in doorman.yaml." : `Off lets everything through unscanned. Turning it on downloads the model if it isn't there yet; turning it off asks for your ${signIn}.` });
  if (locked.has("enabled")) enabled.querySelector("input").disabled = true;
  const threshold = h("input", { type: "number", min: "0.05", max: "0.99", step: "0.05", value: String(g.threshold),
    class: "num", "aria-label": "Threshold", disabled: locked.has("threshold") });
  const save = h("button", {}, "Save");
  save.onclick = () => act(save, () => sensitive("POST", "/owner/guard", { threshold: Number(threshold.value) }),
    () => { toast("Threshold saved"); route(); });
  const settings = section("Settings", h("div", { class: "list" }, h("div", { class: "pad" }, enabled),
    h("div", { class: "pad" }, h("label", { class: "field" }, h("span", { class: "label" }, "Hold back from a score of"),
      h("div", { class: "inline-form" }, threshold, locked.has("threshold") ? null : save),
      h("span", { class: "hint" }, locked.has("threshold") ? "Set in doorman.yaml."
        : `From 0 to 1. Lower holds back more, harmless mail included; higher lets more through and asks for your ${signIn}. 0.5 is the model's own default.`)))));

  const held = list.items.filter((q) => q.status === "held");
  const decided = list.items.filter((q) => q.status !== "held");
  const items = section("Held back", h("div", { class: "list" },
    list.items.length ? [...held, ...decided].map(quarantineRow)
      : h("div", { class: "pad" }, h("p", { class: "muted small" }, "Nothing held back yet."))),
    { count: held.length || undefined,
      note: "One item in a list is left out and the agent sees only that something was held back; a single read is refused. Releasing lets exactly that text through; if it changes, it's scanned again." });

  return [topbar("Injection guard", "#/more"), head("Injection guard", guardSummary(g), h("span", { class: `status ${(GUARD_STATE[g.state] || ["", "quiet"])[1]}` }, (GUARD_STATE[g.state] || [g.state])[0])),
    scanner, settings, items];
};

screens.quarantine = async (id) => {
  const q = await api("GET", `/owner/quarantine/${id}`);
  const [label, cls] = QUARANTINE_STATE[q.status] || [q.status, "quiet"];
  const release = h("button", { class: "primary" }, icon("check", "sm"), "Release to agents");
  release.onclick = async () => {
    const ok = await confirmSheet("Release this to agents?",
      "Agents can read this exact text from now on. If it changes, it's scanned again. Release it only if nothing in it tries to tell an AI what to do.",
      "Release");
    if (ok) act(release, () => api("POST", `/owner/quarantine/${q.id}/release`), () => { clearQuestionPushes((id) => id === q.id, "quarantine"); toast("Released"); location.hash = "#/guard"; });
  };
  const keep = h("button", {}, q.status === "released" ? "Hold it back again" : "Keep it held back");
  keep.onclick = () => act(keep, () => api("POST", `/owner/quarantine/${q.id}/keep`), () => { clearQuestionPushes((id) => id === q.id, "quarantine"); toast("Kept back"); location.hash = "#/guard"; });
  const facts = h("dl", { class: "list facts" },
    [["Where", q.source], ["From", q.sender], ["Reference", q.ref], ["Why", q.reason],
      ["Score", q.reason ? null : q.score.toFixed(2)],
      ["Held back", when(q.created)], ["Decided", q.decided ? when(q.decided) : null]]
      .filter(([, v]) => v).map(([k, v]) => h("div", {}, h("dt", {}, k), h("dd", { class: k === "Reference" ? "mono" : "" }, v))));
  return [topbar("Held back", "#/guard"),
    head(q.label || "An item", q.reason
      ? `No agent got this. Doorman found ${q.reason}: hidden text is a common way to slip instructions to an AI.`
      : "No agent got this. The model scores it as a possible prompt injection: text meant to make an AI do something.",
      h("span", { class: `status ${cls}` }, label)),
    section("The part that scored highest", h("div", { class: "list" }, h("div", { class: "mail-body" }, q.excerpt)),
      { note: "Plain text, as the agent would have got it, minus IDs and references (they aren't scanned); a link's random parts show as …. Look for instructions aimed at an assistant or AI: forward this, ignore that, don't tell the user." }),
    section("Details", facts),
    section(q.status === "held" ? "Decide" : "Change your mind", h("div", { class: "list" },
      h("div", { class: "pad actions" }, q.status === "released" ? null : release, q.status === "kept" ? null : keep)))];
};

// ---------------------------------------------------------------- network watch (the egress proxy)

// The proxy in words: running, quiet for over five minutes, or never heard from.
const proxyState = (st) => (st.up ? ["Running", "ok"] : st.seen ? ["Not responding", "warn"] : ["Not seen yet", "quiet"]);
const proxyLine = (st) => (st.seen ? `Proxy last seen ${relative(st.seen)}` : "Proxy not seen yet");

function byteWords(n) {
  if (n === null || n === undefined) return "0 B";
  if (n < 1000) return `${n} B`;
  const [v, unit] = n < 1e6 ? [n / 1e3, "kB"] : n < 1e9 ? [n / 1e6, "MB"] : [n / 1e9, "GB"];
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${unit}`;
}

const isLeak = (r) => !!r.leak || ["leak", "honeytoken"].includes(r.rule);
const ranWords = (r) => (r.call ? [r.call.tool, r.call.summary].filter(Boolean).join(" · ")
  : r.process ? r.process.cmdline || r.process.exe || "—" : "—");
// Why a connection was blocked, when the proxy sent its rule without a sentence of its own.
const RULE_WORDS = {
  deny_list: "it's on your block list", dns_tunnel: "the name looks like data hidden in DNS",
  countries: "the address is in a country on your list", risky_tlds: "the domain is on the list of ones often used for abuse",
  exfil_upload: "uploads to paste, webhook and tunnel sites are blocked", bare_ip_nonweb: "a non-web connection to a bare IP address",
  nonweb_block: "only web traffic is allowed", leak: "it carried what the agent read through Doorman",
  honeytoken: "it carried protected content (a honeytoken)", doorman_down: "Doorman couldn't check it",
  private: "a private or local address", tls_failed: "the program refused the proxy's certificate", error: "the connection failed",
  raw_on_web_port: "not web traffic on a web port", unscanned: "the upload was too large to check",
  upgrade: "an unknown protocol switch", quarantine: "this agent is stopped: it touched the decoy keys",
};
const REQUEST_KIND = { dns: "Name lookup", tcp: "Connection, not web", tls_failed: "Refused the proxy's certificate" };

// One connection: where to, what it asked, what ran it, how much went each way and what the rules did.
// inCall: on the task screen, under the tool call that made it, which isn't repeated.
function netRow(r, inCall = false) {
  const blocked = r.decision === "deny";
  const where = `${r.host || r.ip || "Unknown host"}${r.port && r.kind !== "dns" ? `:${r.port}` : ""}`;
  const request = REQUEST_KIND[r.kind] || [r.method, r.path].filter(Boolean).join(" ") || null;
  const leak = r.leak ? `About ${r.leak.chars} characters of what the agent read${(r.leak.sources || []).length ? `: ${r.leak.sources.join(", ")}` : ""}.` : null;
  return h("div", { class: "net-row" },
    h("div", { class: "line1" }, h("span", { class: "where" }, where),
      h("span", { class: "tags" }, isLeak(r) ? h("span", { class: "tag send" }, icon("warn", "sm"), "Leak") : null,
        h("span", { class: `tag ${blocked ? "danger" : "off"}` }, blocked ? "Blocked" : "Allowed"))),
    request ? h("div", { class: "req" }, request) : null,
    inCall ? null : h("div", { class: "ran" }, ranWords(r)),
    blocked && !leak && (r.detail || RULE_WORDS[r.rule]) ? h("p", { class: "why" }, sentence(r.detail || RULE_WORDS[r.rule])) : null,
    leak ? h("p", { class: "why" }, leak) : null,
    h("p", { class: "meta num" }, `${clock(r.ts)} · ↑ ${byteWords(r.bytes_up)} ↓ ${byteWords(r.bytes_down)}`,
      r.outside_call ? [" · ", h("span", { class: "look" }, icon("warn", "sm"), "No tool call running")] : null));
}

// Newest first, under a heading per day.
function netLog(rows) {
  const out = [];
  let last = null;
  for (const r of rows) {
    const d = (r.ts || "").slice(0, 10);
    if (!last || last.day !== d) {
      last = { day: d, list: h("div", { class: "list" }) };
      out.push(h("section", { class: "group" }, h("div", { class: "group-head" }, h("h2", {}, day(d))), last.list));
    }
    last.list.append(netRow(r));
  }
  return out;
}

// The proxy's token: shown once, with the line for deploy/.env. A new one replaces the old.
async function proxyToken(button) {
  act(button, () => sensitive("POST", "/owner/egress/token"), async (out) => {
    await sheet({ title: "Token for the proxy", cancel: "Done",
      body: [warnRow("The token is shown only now. Copy it before you close this."),
        h("p", {}, "Put this line in deploy/.env next to Doorman, with COMPOSE_FILE set to compose.yaml:compose.egress.yaml and your agent's file (compose.hermes.yaml for Hermes), then start the proxy and the agent behind it: docker compose up -d."),
        copyBlock("For deploy/.env", `DOORMAN_EGRESS_TOKEN=${out.token}`)] });
    route();
  });
}

const lines = (text) => text.split("\n").map((l) => l.trim()).filter(Boolean);
const sameList = (a, b) => a.length === b.length && [...a].sort().join("\n") === [...b].sort().join("\n");
const numberWords = (n) => Number(n).toLocaleString();

// The owner's rules, as one form with one Save: switches, lists one per line, numbers.
function networkForm(s, builtIn) {
  const keep = (k) => `egress:${k}`;
  const cats = s.categories || {};
  const tlds = s.risky_tlds || builtIn.risky_tlds;
  const hosts = s.exfil_hosts || builtIn.exfil_hosts;
  const countries = h("input", { type: "text", value: s.countries.join(", "), autocapitalize: "characters", spellcheck: "false",
    "aria-label": "Country codes", "data-keep": keep("countries") });
  const listField = (key, label, hint, value, rows = 4) => {
    const area = h("textarea", { rows, autocapitalize: "off", spellcheck: "false", class: "mono-area", "data-keep": keep(key) }, value.join("\n"));
    return { area, row: h("label", { class: "field" }, h("span", { class: "label" }, label), area, hint ? h("span", { class: "hint" }, hint) : null) };
  };
  const tldList = listField("risky_tlds", "Domains on the list", "One per line, without the dot. Empty the field to block none.", tlds, 6);
  const hostList = listField("exfil_hosts", "Sites on the list", "One per line. A site covers its subdomains.", hosts, 6);
  const sw = (key, checked, label, hint) => localSwitch(checked, label, hint, keep(key));
  const switches = {
    exfil_upload: sw("exfil_upload", cats.exfil_upload !== false, "Uploads to paste, webhook and tunnel sites", "Reading from them still works."),
    risky_tlds: sw("risky_tlds", cats.risky_tlds !== false, `Domains often used for abuse (${tlds.slice(0, 2).map((t) => `.${t}`).join(", ")}, …)`, null),
    countries: sw("countries", cats.countries !== false, `Countries: ${s.countries.join(", ") || "none"}`, "Where an address is, from a free country database the proxy keeps."),
    bare_ip_nonweb: sw("bare_ip_nonweb", cats.bare_ip_nonweb !== false, "Non-web connections to bare IP addresses", "When no name lookup led to the address."),
    dns_tunnel: sw("dns_tunnel", cats.dns_tunnel !== false, "Data hidden in DNS lookups", "Names too long or too random to be a real site."),
  };
  const countryLabel = switches.countries.row.querySelector(".grow > span");
  countries.addEventListener("input", () => {
    countryLabel.textContent = `Countries: ${countries.value.split(/[\s,]+/).filter(Boolean).join(", ").toUpperCase() || "none"}`;
  });

  const nonweb = sw("nonweb", s.nonweb === "block", "Block connections that aren't web traffic",
    `Web is ports ${s.web_ports.join(", ")}. Off: other connections are logged and let through.`);
  const down = sw("when_doorman_down", s.when_doorman_down === "block", "Block what can't be checked while Doorman is down",
    "Off: a request Doorman couldn't check goes out unchecked. On: it doesn't, so the agent can't send anything while Doorman is down or busy.");
  const unscanned = sw("unscanned", (s.unscanned || "block") === "block", "Block uploads too large to check",
    "Too big for the proxy to read through, to a site not on your allow list. Off: they're let through unchecked.");
  const own = {
    allow: listField("allow", "Always allow", "Let through before any rule above.", s.allow),
    deny: listField("deny", "Always block", "Blocked even when a rule would let it through.", s.deny),
    no_scan: listField("no_scan", "Not checked for your data", "Your model provider, for example: the agent sends it what it read all the time.", s.no_scan),
    passthrough: listField("passthrough", "Left unopened", "For apps that refuse the proxy's certificate. Nothing in them is checked.", s.passthrough),
  };
  const leakBlock = sw("leak_action", s.leak_action === "block", "Block requests that carry what the agent read",
    "Off: they go out and you're told. On: they don't, the agent's key is paused until you resume it, and you're told each time.");
  const num = (key, label, unit, hint) => {
    const input = h("input", { type: "number", inputmode: "numeric", value: String(s[key]), class: "num", "data-keep": keep(key), "aria-label": label });
    return { input, row: h("label", { class: "field" }, h("span", { class: "label" }, label),
      h("span", { class: "with-unit" }, input, h("span", { class: "meta" }, unit)), hint ? h("span", { class: "hint" }, hint) : null) };
  };
  const nums = {
    leak_chars: num("leak_chars", "A leak from", "characters", "Of text the agent read through Doorman, found in one request."),
    note_chars: num("note_chars", "Noted in the log from", "characters", null),
    match_hours: num("match_hours", "Remember what it read for", "hours", null),
    large_upload_mb: num("large_upload_mb", "Tell me about uploads to a new site from", "MB", "0 turns this off."),
    log_days: num("log_days", "Keep the log for", "days", null),
  };

  const tldsOut = () => { const t = lines(tldList.area.value).map((x) => x.replace(/^\./, "").toLowerCase()); return sameList(t, builtIn.risky_tlds) ? null : t; };
  const hostsOut = () => { const t = lines(hostList.area.value).map((x) => x.toLowerCase()); return sameList(t, builtIn.exfil_hosts) ? null : t; };
  const read = () => ({
    categories: Object.fromEntries(Object.entries(switches).map(([k, v]) => [k, v.box.checked])),
    countries: countries.value.split(/[\s,]+/).filter(Boolean).map((c) => c.toUpperCase()),
    risky_tlds: tldsOut(), exfil_hosts: hostsOut(),
    nonweb: nonweb.box.checked ? "block" : "log", when_doorman_down: down.box.checked ? "block" : "allow",
    unscanned: unscanned.box.checked ? "block" : "allow",
    ...Object.fromEntries(Object.entries(own).map(([k, v]) => [k, lines(v.area.value)])),
    leak_action: leakBlock.box.checked ? "block" : "alert",
    ...Object.fromEntries(Object.entries(nums).map(([k, v]) => [k, v.input.value === "" ? s[k] : Number(v.input.value)])),
  });
  const saved = JSON.stringify(read());

  const save = h("button", { class: "primary", type: "button" }, "Save");
  const discard = h("button", { class: "quiet plain", type: "button" }, "Undo changes");
  const bar = h("div", { class: "save-bar", hidden: true, role: "group", "aria-label": "Unsaved changes" },
    h("span", { class: "grow meta" }, "Not saved yet"), discard, save);
  const form = h("div", { class: "net-form" },
    section("Blocked by default", h("div", { class: "list" },
      switches.exfil_upload.row,
      disclose(`Sites on the list: ${hosts.length}`, hostList.row, { keep: keep("hosts-open") }),
      switches.risky_tlds.row,
      disclose(`Domains on the list: ${tlds.length}`, tldList.row, { keep: keep("tlds-open") }),
      switches.countries.row,
      h("div", { class: "pad" }, h("label", { class: "field" }, h("span", { class: "label" }, "Country codes"), countries,
        h("span", { class: "hint" }, "Two letters each, separated by commas."))),
      switches.bare_ip_nonweb.row, switches.dns_tunnel.row),
    { note: "What the proxy blocks for every agent, without asking you. The agent can ask you to let something through." }),
    section("Other connections", h("div", { class: "list" }, nonweb.row, down.row, unscanned.row)),
    section("Your lists", h("div", { class: "list" }, h("div", { class: "pad" }, Object.values(own).map((o) => o.row))),
      { note: "One per line: example.com (and its subdomains), *.example.com (only subdomains), 1.2.3.4 or 10.0.0.0/8, each with :port if you like." }),
    section("Leaks", h("div", { class: "list" }, leakBlock.row, h("div", { class: "pad" }, Object.values(nums).map((n) => n.row))),
      { note: "The proxy compares what goes out with what the agent read through Doorman: mail, files, chats. Only fingerprints are compared; the text never leaves Doorman." }),
    bar);
  for (const r of Object.values(switches).concat([nonweb, down, unscanned, leakBlock])) r.row.classList.add("pad-x");

  const check = () => { bar.hidden = JSON.stringify(read()) === saved; };
  form.addEventListener("input", check);
  form.addEventListener("change", check);
  requestAnimationFrame(check);  // after a re-render brought back what was typed
  save.onclick = () => act(save, () => sensitive("POST", "/owner/egress", read()), () => {
    forget(form);
    toast("Saved. The proxy uses it within seconds.");
    route();
  });
  discard.onclick = () => { forget(form); route(); };
  return form;
}

function exemptionRow(e) {
  const scope = e.scope === "task" ? `For task ${e.task_id}` : e.scope === "once" ? `Until ${clock(e.expires)}` : e.scope;
  return h("div", { class: "row-item" }, icon("globe"), h("div", { class: "grow" },
    h("div", { class: "primary-text mono-strong" }, e.target),
    h("div", { class: "secondary-text" }, `${scope} · ${e.agent || "an agent"} asked`)),
    removeButton("Revoke", () => api("POST", `/owner/egress/exemptions/${e.id}/revoke`),
      { aria: `Revoke the exception for ${e.target}`, done: () => toast(`The exception for ${e.target} ended`) }));
}

// The API keys the agent used with model providers (no_scan hosts), by a short fingerprint of each. A second
// key for one provider is flagged: it may be someone else's account, a way out the leak check doesn't read.
function modelKeys(keys) {
  const perHost = {};
  for (const k of keys) perHost[k.host] = (perHost[k.host] || 0) + 1;
  const rows = keys.map((k) => h("div", { class: "row-item" }, icon("key"), h("div", { class: "grow" },
    h("div", { class: "primary-text" }, h("span", { class: "mono-strong" }, k.host), " ",
      h("span", { class: "mono" }, k.auth_hash.slice(0, 8))),
    h("div", { class: "secondary-text" }, `First ${when(k.first_seen)} · last ${relative(k.last_seen)} · ${plural(k.count, "request", "requests")}`)),
    perHost[k.host] > 1 ? h("span", { class: "tag send" }, icon("warn", "sm"), `${perHost[k.host]} keys`) : null));
  return section("API keys used with model providers", h("div", { class: "list" }, rows.length ? rows
    : h("div", { class: "pad" }, h("p", { class: "muted small" }, "None seen yet."))),
  { note: "What goes to a model provider isn't checked for your data. Each key the agent used there is listed by a short fingerprint; a second key for the same provider may be someone else's account." });
}

// An agent that touched the decoy keys: the proxy gives its address nothing until the owner lets it out
// (or resumes its key, which does the same). Its key stays paused either way.
function quarantineBanner(q) {
  const names = (q.agents || []).map((a) => `“${a}”`);
  const who = names.length === 1 ? `Agent ${names[0]} is` : names.length ? `Agents ${names.join(", ")} are` : `The agent at ${q.client_ip} is`;
  const out = h("button", { class: "primary", type: "button" }, "Let it out again");
  out.onclick = async () => {
    if (!await confirmSheet(`Let ${q.client_ip} out again?`,
      "The proxy lets its connections through again. Its key stays paused until you resume it under More → Agents; resuming the key lets it out too.",
      "Let it out again")) return;
    act(out, () => sensitive("POST", "/owner/egress/quarantine/lift", { client_ip: q.client_ip }), () => {
      toast(`${q.client_ip} can reach the network again`);
      route();
    });
  };
  return warnRow([h("strong", { class: "warn-title" }, `${who} stopped: it touched the decoy keys`),
    h("span", { class: "warn-text" }, `${sentence(`${q.reason}, ${relative(q.since)}`)} The proxy gives ${q.client_ip} nothing at all, model providers included, and the key is paused.`),
    h("div", { class: "actions mt-2" }, out)], "danger");
}

// Fake API keys in the agent's container that it's told never to touch: only something steering it would.
const TRIP_WORDS = { open: "Opened", access: "Read" };
function decoySection(d) {
  const set = async (change, said) => {
    await sensitive("POST", "/owner/egress", { decoys: change });
    toast(said);
    route();
  };
  const onOff = toggle(d.enabled, "Decoy keys in the agent's container", (on) => set({ enabled: on },
    on ? "Decoy keys on. The proxy puts the file back within seconds." : "Decoy keys off. The proxy removes the file."),
  { hint: "A file of fake API keys in ~/.config/secrets/. The agent is told never to touch it." });
  onOff.classList.add("pad-x");
  const onTrip = modeControl([
    ["quarantine", "Stop the agent", "Pause its key and cut it off from the network"],
    ["alert", "Only tell me", "A push and an item in the inbox; nothing is stopped"]],
  d.on_trip, (mode) => set({ on_trip: mode }, mode === "quarantine" ? "Touching the decoy keys stops the agent" : "Touching the decoy keys only tells you"),
  "When they're touched");
  const trip = d.last_trip;
  const renew = h("button", { class: "quiet plain", type: "button" }, "Make new keys");
  renew.onclick = async () => {
    if (await confirmSheet("Make new decoy keys?", "The proxy replaces the file within seconds. The old keys still stop an agent that uses them.", "Make new keys"))
      act(renew, () => sensitive("POST", "/owner/egress/decoys/rotate"), () => { toast("New decoy keys made"); route(); });
  };
  return section("Decoy keys", [
    h("div", { class: "list" }, onOff,
      d.enabled ? h("div", { class: "pad" }, h("div", { class: "tool-row modal" }, h("div", { class: "grow" },
        h("div", { class: "tname" }, "When they're touched"),
        h("div", { class: "meta" }, d.on_trip === "quarantine"
          ? "Its key is paused and the proxy cuts it off, until you let it out."
          : "You're told; the agent carries on.")), onTrip)) : null),
    h("div", { class: "list mt-3" },
      h("dl", { class: "facts" },
        h("div", {}, h("dt", {}, "Last touched"), h("dd", {}, trip ? `${TRIP_WORDS[trip.event] || "Touched"} ${when(trip.ts)}` : "Never")),
        h("div", {}, h("dt", {}, "Made"), h("dd", {}, d.created ? when(d.created) : "When the proxy first asks"))),
      h("div", { class: "pad" }, h("div", { class: "quiet-row tight" }, renew)))],
  { note: "Using one of them, in a request or a tool call, counts like reading them. A backup of Docker volumes on the host would read them too: leave the agent-config volume out." });
}

const NET_FILTERS = [["all", "All"], ["blocked", "Blocked"], ["leaks", "Leaks"]];
const NET_PAGE = 25;

function netRecent() {
  let only = "all";
  let oldest = null;
  const body = h("div", {});
  const more = h("button", { class: "quiet", type: "button" }, "Show older");
  const load = async (append) => {
    const out = await api("GET", `/owner/egress/log?only=${only}&limit=${NET_PAGE}${append && oldest ? `&before=${oldest}` : ""}`);
    if (out.rows.length) oldest = out.rows[out.rows.length - 1].id;
    more.hidden = out.rows.length < NET_PAGE;
    if (!append) body.replaceChildren();
    if (!append && !out.rows.length) body.append(h("div", { class: "empty compact" }, h("p", {},
      only === "all" ? "No connections yet. Once the agent goes online, each connection shows up here." : only === "blocked" ? "Nothing blocked." : "No leaks found.")));
    body.append(...netLog(out.rows));
  };
  more.onclick = () => act(more, () => load(true));
  const segs = h("div", { class: "segs", role: "group", "aria-label": "Show" }, NET_FILTERS.map(([value, label]) => {
    const b = h("button", { class: `seg${value === only ? " on" : ""}`, type: "button", "aria-pressed": String(value === only) }, label);
    b.onclick = () => act(b, async () => {
      only = value; oldest = null;
      for (const x of segs.children) { const on = x === b; x.classList.toggle("on", on); x.setAttribute("aria-pressed", String(on)); }
      await load(false);
    });
    return b;
  }));
  return { first: () => load(false), el: section("Recent", [h("div", { class: "tools" }, segs), body, h("div", { class: "actions" }, more)],
    { note: "Each connection with the tool call or program that made it. “No tool call running” means something talked to the internet while the agent wasn't running a tool." }) };
}

screens.network = async () => {
  const n = await api("GET", "/owner/egress");
  if (!n.enabled) {
    const setup = h("button", { class: "primary" }, "Set up the proxy");
    setup.onclick = () => proxyToken(setup);
    return [topbar("Network", "#/more"),
      head("Network", "Off. The agent reaches the internet without Doorman seeing it."),
      section("Watch what the agent sends out", h("div", { class: "list" }, h("div", { class: "pad" },
        h("p", { class: "prose mb-4" }, "A proxy next to the agent's container passes everything it sends to the internet. It logs each connection with the tool call that made it, blocks what your rules say, and stops requests that carry what the agent read through Doorman."),
        h("ol", { class: "setup-steps" },
          h("li", {}, "Set up the proxy here. Doorman makes a token for it."),
          h("li", {}, "Put the token in deploy/.env and start the proxy with the agent behind it (deploy/egress/README.md)."),
          h("li", {}, "The agent's connections show up here. When a rule blocks something it needs, it asks you in the inbox.")),
        h("div", { class: "actions" }, setup))))];
  }
  const [ex, recent] = [await api("GET", "/owner/egress/exemptions"), netRecent()];
  await recent.first();
  const st = n.status;
  const geo = st.proxy && st.proxy.geoip;
  const c = n.counts;
  const status = section("Today", h("dl", { class: "list facts" },
    h("div", {}, h("dt", {}, "Proxy"), h("dd", {}, st.seen ? `Last seen ${relative(st.seen)}` : "Not seen yet")),
    h("div", {}, h("dt", {}, "Country data"), h("dd", {}, geo && geo.rows ? `${numberWords(geo.rows)} ranges${geo.date ? `, ${geo.date}` : ""}` : "None yet: the country rule can't match")),
    h("div", {}, h("dt", {}, "Connections"), h("dd", { class: "num" }, numberWords(c.today))),
    h("div", {}, h("dt", {}, "Blocked"), h("dd", { class: "num" }, numberWords(c.blocked_today))),
    h("div", {}, h("dt", {}, "Leaks found"), h("dd", { class: "num" }, numberWords(c.leaks_today)))));
  const exceptions = section("Exceptions", h("div", { class: "list" }, ex.exemptions.length ? ex.exemptions.map(exemptionRow)
    : h("div", { class: "pad" }, h("p", { class: "muted small" }, "None right now. When you allow a request once or for a task, it shows here until it ends."))),
    { count: ex.exemptions.length || undefined });
  const renew = h("button", { class: "quiet plain", type: "button" }, "Make a new token");
  renew.onclick = async () => {
    if (await confirmSheet("Make a new token?", "The old one stops working at once. The proxy can't reach Doorman until it has the new one, and until then it does what you set for Doorman being down.", "Make a new token"))
      proxyToken(renew);
  };
  const [word, cls] = proxyState(st);
  const sub = `${proxyLine(st)}. Everything the agent sends to the internet passes the proxy: it logs each connection, applies your rules and blocks requests that carry what the agent read.`;
  const stopped = n.quarantine || [];
  return [topbar("Network", "#/more"), head("Network", sub, h("span", { class: `status ${cls}` }, word)),
    stopped.length ? h("div", { class: "warns mb-section", role: "alert" }, stopped.map(quarantineBanner)) : null,
    st.seen && !st.up ? h("div", { class: "warns mb-section" }, warnRow("The proxy hasn't called in for over five minutes. If it's stopped, the agent has no internet at all; if it runs without Doorman, it does what you set for Doorman being down.")) : null,
    status, exceptions, recent.el, modelKeys(n.model_keys || []), n.decoys ? decoySection(n.decoys) : null,
    networkForm(n.settings, n.lists),
    section("Proxy token", h("div", { class: "list" }, h("div", { class: "pad" },
      h("p", { class: "muted small" }, "The proxy signs in to Doorman with it (DOORMAN_EGRESS_TOKEN). Make a new one if it may have leaked."),
      h("div", { class: "quiet-row tight" }, renew))))];
};

const DETAIL_SCREENS = ["approvals", "review", "changesets", "task", "status", "privacy", "guard", "quarantine", "semantic", "network"];  // pushed screens with a back link, no tab bar on phones
const LIVE_SCREENS = ["inbox", "journal", "tasks", "task", "approvals", "review", "changesets", "status", "guard"];  // re-fetched when the app comes back
let current = null;
let doormanPaused = false;
let shownKey = null;  // the screen on display, for the direction of the next transition
let routing = 0;

// A re-render of the same screen (after a save or a toggle) keeps what the owner typed but didn't save
// yet and which sections they had open. Elements opt in with data-keep, a key stable across renders.
function keptState(root) {
  const kept = new Map();
  for (const el of root.querySelectorAll("[data-keep]")) {
    if (el.tagName === "DETAILS") kept.set(el.dataset.keep, { open: el.open });
    else if (el.type === "checkbox") { if (el.checked !== el.defaultChecked) kept.set(el.dataset.keep, { checked: el.checked }); }
    else if (el.value !== el.defaultValue) kept.set(el.dataset.keep, { value: el.value });
  }
  return kept;
}

function restoreState(root, kept) {
  for (const el of root.querySelectorAll("[data-keep]")) {
    const s = kept.get(el.dataset.keep);
    if (!s) continue;
    if ("open" in s) el.open = s.open;
    else if ("checked" in s) el.checked = s.checked;
    else el.value = s.value;
  }
}

// Done with a form (it was sent): back to its defaults and closed, so the next render doesn't bring it back.
function forget(root) {
  for (const el of root.querySelectorAll("input, textarea, select")) {
    if (el.type === "checkbox") el.checked = el.defaultChecked; else el.value = el.defaultValue;
  }
  if (root.tagName === "DETAILS") root.open = false;
}

async function route(opts = {}) {
  const [, name = "inbox", ...args] = (location.hash || "#/inbox").split("/");
  const screen = screens[name] || screens.inbox;
  const key = screens[name] ? name : "inbox";
  const open = PUBLIC_SCREENS.includes(key);
  const navigated = current !== location.hash;
  current = location.hash;
  const run = ++routing;

  tabs.hidden = open || DETAIL_SCREENS.includes(key);
  shell.classList.toggle("bare", tabs.hidden);
  if (DETAIL_SCREENS.includes(key) && window.matchMedia("(min-width: 900px)").matches) { tabs.hidden = false; shell.classList.remove("bare"); }
  for (const a of tabs.querySelectorAll("a")) {
    const tab = ["status", "privacy", "guard", "quarantine", "semantic", "network"].includes(key) ? "more" : key === "task" ? "tasks" : key;
    if (a.dataset.tab === tab) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  }
  const slow = navigated ? setTimeout(() => { if (run === routing) view.replaceChildren(skeleton()); }, 150) : null;
  try {
    const settings = open ? null : await api("GET", "/owner/settings").catch(() => null);
    if (settings || open) doormanPaused = !!(settings && settings.paused);  // offline: what was known stays
    document.getElementById("paused").hidden = !doormanPaused;
    if (doormanPaused && settings) document.querySelector("#paused span").textContent = settings.agent_keys
      ? "Paused: agents' calls are refused" : "Stopped: every agent key was revoked";
    if (settings) approvalPasskey = !!settings.approval_passkey;
    if (settings) signIn = settings.sign_in || "passkey";
    const content = await screen(...args);
    if (run !== routing) return;  // a newer navigation won
    clearTimeout(slow);
    if (content) {
      const scroll = window.scrollY;
      const kept = navigated ? null : keptState(view);
      view.replaceChildren(...[content].flat(3).filter(Boolean));
      if (kept) restoreState(view, kept);
      const bar = !!view.querySelector(".decision-bar");
      view.classList.toggle("has-bar", bar);
      shell.classList.toggle("has-bar", bar);
      if (navigated) {
        const into = DETAIL_SCREENS.includes(key), from = DETAIL_SCREENS.includes(shownKey);
        view.classList.remove("enter", "push", "pop"); void view.offsetWidth;
        view.classList.add("enter", ...(shownKey && into && !from ? ["push"] : from && !into ? ["pop"] : []));
        shownKey = key;
        window.scrollTo(0, 0);
        if (opts.fromHash) view.focus({ preventScroll: true });
      } else window.scrollTo(0, scroll);
    }
    if (!open) {
      if (key !== "inbox") refreshBadge();
      syncPush().catch(() => {});
    }
  } catch (err) {
    clearTimeout(slow);
    if (run === routing && location.hash !== "#/login") view.replaceChildren(problem(err));
  }
}

window.addEventListener("hashchange", () => route({ fromHash: true }));
// Fetch the screen again when nothing the owner is doing would be lost: no sheet open, nothing being typed.
function refreshIfIdle() {
  const name = (location.hash || "#/inbox").split("/")[1] || "inbox";
  const typing = view.querySelector(".edit-form") || (document.activeElement && view.contains(document.activeElement)
    && /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName));
  if (LIVE_SCREENS.includes(name) && !document.querySelector("dialog[open]") && !typing) route();
}
// Coming back to the app (e.g. from a notification) shows fresh approvals.
document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") refreshIfIdle(); });
// Offline: the banner says so at once; back online, the screen is fetched again.
window.addEventListener("offline", () => setOffline(true));
window.addEventListener("online", () => { setOffline(false); if (view.querySelector(".problem")) route(); else refreshIfIdle(); });
setOffline(false);
if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js").catch(() => {});
route();
