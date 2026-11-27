// ย้ายเว็บไปที่อยู่ใหม่: เว็บเดิม (github.io / netlify.app) ขึ้นแถบบอกพร้อมปุ่มพาไปหน้าเดียวกันบน NEW_HOME
// จะขึ้นแถบบอกพร้อมปุ่มพาไปหน้าเดียวกัน รหัสสาขาที่เครื่องจำไว้ติดไปด้วย ไม่ต้องวางลิงก์ใหม่
(function(){
  var NEW_HOME = "https://rosjana-clock.web.app/";
  if (!NEW_HOME || !/(github\.io|netlify\.app)$/.test(location.hostname)) return;
  var page = location.pathname.split("/").pop() || "index.html";
  var url = new URL(page, NEW_HOME);
  url.search = location.search;
  if (!url.searchParams.get("b") && page !== "admin.html"){
    var k = "";
    try{ k = localStorage.getItem("clock_key") || localStorage.getItem("calendar_key") || ""; } catch(e){}
    if (/^[a-f0-9]{8,64}$/i.test(k)) url.searchParams.set("b", k);
  }
  function show(){
    var bar = document.createElement("div");
    bar.style.cssText = "position:fixed;left:0;right:0;top:0;z-index:99999;background:#0f172a;color:#fff;padding:14px 16px;text-align:center;font:700 15px/1.6 system-ui,sans-serif;box-shadow:0 4px 16px rgba(0,0,0,.3);";
    bar.innerHTML = "📢 เว็บย้ายไปที่อยู่ใหม่แล้ว · <span lang='my'>ဝဘ်ဆိုက် လိပ်စာအသစ်သို့ ပြောင်းပြီးပါပြီ</span> · This page has moved" +
      "<br><a style='display:inline-block;margin-top:8px;background:#22c55e;color:#fff;padding:10px 18px;border-radius:10px;text-decoration:none;font-weight:900;'></a>" +
      "<div style='font-size:12.5px;font-weight:600;opacity:.85;margin-top:6px;'>เปิดแล้วเพิ่มลงหน้าจอโฮมใหม่ และลบไอคอนเก่า</div>";
    var a = bar.querySelector("a");
    a.href = url.toString();
    a.textContent = "👉 เปิดเว็บใหม่ · Open";
    document.body.appendChild(bar);
  }
  if (document.body) show(); else document.addEventListener("DOMContentLoaded", show);
})();
