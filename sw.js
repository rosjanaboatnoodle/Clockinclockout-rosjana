// แจ้งเตือนของระบบตอกบัตร: รับข้อความจากเซิร์ฟเวอร์แล้วแสดงบนหน้าจอ กดแล้วเปิดหน้าที่เกี่ยวข้อง
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));

self.addEventListener("push", (e) => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (_) { d = { title: e.data ? e.data.text() : "" }; }
  e.waitUntil(self.registration.showNotification(d.title || "ตอกบัตร", {
    body: d.body || "",
    tag: d.tag || undefined,
    icon: "icon-192.png",
    badge: "icon-192.png",
    data: { url: d.url || "./index.html" },
  }));
});

self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  const url = new URL((e.notification.data && e.notification.data.url) || "./index.html", self.registration.scope).href;
  e.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((list) => {
    for (const c of list) if (c.url.split("?")[0] === url.split("?")[0] && "focus" in c) return c.focus();
    return self.clients.openWindow(url);
  }));
});
