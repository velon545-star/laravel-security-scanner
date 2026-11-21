#!/usr/bin/env python3
"""
فاحص Laravel الأمني – النسخة 1.0
作者: جموح (JUMOOH)
الاستخدام: python laravel_security_scanner.py /path/to/laravel/project
المخرجات: تقرير نصي + JSON
"""

import os
import re
import json
import sys
import hashlib
from pathlib import Path

# أنماط الكشف عن الثغرات الشائعة
PATTERNS = {
    "exposed_env": {
        "pattern": r"APP_KEY\s*=\s*base64:",
        "severity": "CRITICAL",
        "desc": ".env مكشوف أو يحتوي على مفتاح التطبيق بشكل غير آمن",
        "file": ".env",
        "remediation": "تأكد أن .env ليس في مجلد public ولا في مستودع Git. استخدم APP_KEY من متغير بيئة آمن."
    },
    "debug_true": {
        "pattern": r"APP_DEBUG\s*=\s*true",
        "severity": "HIGH",
        "desc": "وضع التصحيح مُفعّل في الإنتاج – يكشف تفاصيل حساسة",
        "file": ".env",
        "remediation": "اجعل APP_DEBUG=false في بيئة الإنتاج."
    },
    "sql_injection_raw": {
        "pattern": r"DB::raw\(|->whereRaw\(|->havingRaw\(|->selectRaw\(",
        "severity": "HIGH",
        "desc": "استعلامات SQL خام قد تكون عرضة لـ SQL Injection",
        "file": "*.php",
        "remediation": "استخدم Eloquent bindings أو pa...urated queries. لا تستخدم مدخلات المستخدم مباشرة في DB::raw."
    },
    "xss_unescaped": {
        "pattern": r"\{!!\s*\$",
        "severity": "HIGH",
        "desc": "عرض بيانات غير مهرّبة – عرضة لـ XSS",
        "file": "*.blade.php",
        "remediation": "استخدم {{ $var }} بدلاً من {!! $var !!} إلا إذا كنت تثق تماماً في البيانات."
    },
    "csrf_disabled": {
        "pattern": r"VerifyCsrfToken|Veil}",
        "severity": "MEDIUM",
        "desc": "التحقق من CSRF معطل أو مخصص بشكل غير آمن",
        "file": "*.php",
        "remediation": "تأكد من تفعيل CSRF middleware لجميع طلبات POST/PUT/DELETE."
    },
    "file_upload_unsafe": {
        "pattern": r"->store\(|move_uploaded_file|Storage::put",
        "severity": "HIGH",
        "desc": "رفع ملفات دون تحقق كافٍ من النوع أو الامتداد",
        "file": "*.php",
        "remediation": "تحقق من نوع MIME الحقيقي، حدد الامتدادات المسموحة، وعدّل أسماء الملفات تلقائياً."
    },
    "password_hash_weak": {
        "pattern": r"md5\(|sha1\(|crypt\('|password_hash.*PASSWORD_DEFAULT",
        "severity": "CRITICAL",
        "desc": "خوارزمية تجزئة كلمة المرور ضعيفة",
        "file": "*.php",
        "remediation": "استخدم bcrypt أو Argon2i/Argon2id عبر Laravel Hash facade."
    },
    "mass_assignment": {
        "pattern": r"::\$guarded\s*=\s*\[\]|:fillable\s*=\s*\[\s*'\*'\s*\]",
        "severity": "HIGH",
        "desc": "Mass assignment غير مقيد – يمكن تعديل حقول حساسة",
        "file": "Models/*.php",
        "remediation": "حدد $fillable أو $guarded بشكل صارم. لا تستخدم guarded=[]."
    },
    "open_redirect": {
        "pattern": r"redirect\(|Redirect::to\(|return redirect\(\)->away\(",
        "severity": "MEDIUM",
        "desc": "عمليات إعادة توجيه قد تكون مفتوحة (Open Redirect)",
        "file": "*.php",
        "remediation": "تحقق من وجهة إعادة التوجيه مقابل قائمة بيضاء."
    },
    "insecure_cookie": {
        "pattern": r"SESSION_SECURE_COOKIE\s*=\s*false|setcookie\(.*secure\s*=\s*false",
        "severity": "MEDIUM",
        "desc": "كوكيز الجلسة غير محمية – عرضة للاختطاف",
        "file": ".env|config/session.php",
        "remediation": "اجعل SESSION_SECURE_COOKIE=true و استخدم HTTPS دائماً."
    }
}

def scan_project(root_path):
    """يفحص مشروع Laravel كامل ويرجع النتائج"""
    results = []
    root = Path(root_path)
    
    if not root.exists():
        return {"error": f"المسار غير موجود: {root_path}"}
    
    # فحص ملف .env
    env_file = root / ".env"
    if env_file.exists():
        content = env_file.read_text(errors='ignore')
        for name, pattern_info in PATTERNS.items():
            if "file" in pattern_info and pattern_info["file"] == ".env":
                if re.search(pattern_info["pattern"], content):
                    results.append({
                        "file": ".env",
                        "line": "N/A",
                        "issue": name,
                        "severity": pattern_info["severity"],
                        "description": pattern_info["desc"],
                        "remediation": pattern_info["remediation"]
                    })
    
    # فحص ملفات PHP و Blade
    for ext in ["*.php", "*.blade.php"]:
        for file in root.rglob(ext):
            try:
                content = file.read_text(errors='ignore')
                rel_path = str(file.relative_to(root))
                
                for name, pattern_info in PATTERNS.items():
                    file_filter = pattern_info.get("file", "*")
                    if file_filter != "*" and not rel_path.endswith(file_filter.replace("*.", "")):
                        continue
                    
                    for match in re.finditer(pattern_info["pattern"], content, re.IGNORECASE):
                        line_num = content[:match.start()].count('\n') + 1
                        results.append({
                            "file": rel_path,
                            "line": line_num,
                            "issue": name,
                            "severity": pattern_info["severity"],
                            "description": pattern_info["desc"],
                            "remediation": pattern_info["remediation"],
                            "match": match.group()[:100]
                        })
            except Exception:
                continue
    
    # تجميع حسب الخطورة
    by_severity = {}
    for r in results:
        sev = r["severity"]
        by_severity.setdefault(sev, []).append(r)
    
    summary = {
        "total_issues": len(results),
        "by_severity": {k: len(v) for k, v in by_severity.items()},
        "critical": by_severity.get("CRITICAL", []),
        "high": by_severity.get("HIGH", []),
        "medium": by_severity.get("MEDIUM", []),
        "low": by_severity.get("LOW", [])
    }
    
    return {
        "project": str(root),
        "summary": summary,
        "results": results,
        "by_severity": by_severity
    }

def print_report(data):
    """يطبع تقرير مقروء"""
    print("=" * 70)
    print("  تقرير فحص Laravel الأمني – بواسطة جموح (JUMOOH)")
    print("=" * 70)
    
    if "error" in data:
        print(f"\nخطأ: {data['error']}")
        return
    
    print(f"\nالمشروع: {data['project']}")
    print(f"إجمالي المشاكل: {data['summary']['total_issues']}")
    print(f"  - Critical: {data['summary']['by_severity'].get('CRITICAL', 0)}")
    print(f"  - High:     {data['summary']['by_severity'].get('HIGH', 0)}")
    print(f"  - Medium:   {data['summary']['by_severity'].get('MEDIUM', 0)}")
    print(f"  - Low:      {data['summary']['by_severity'].get('LOW', 0)}")
    
    if data['summary']['critical']:
        print("\n" + "!" * 70)
        print("! CRITICAL – يجب إصلاح هذه المشاكل فوراً")
        print("!" * 70)
        for item in data['summary']['critical']:
            print(f"\n  [{item['file']}:{item['line']}] {item['description']}")
            print(f"  العلاج: {item['remediation']}")
    
    if data['summary']['high']:
        print("\n" + "-" * 70)
        print("- HIGH – مشاكل أمنية مهمة")
        print("-" * 70)
        for item in data['summary']['high']:
            print(f"\n  [{item['file']}:{item['line']}] {item['description']}")
            print(f"  العلاج: {item['remediation']}")
    
    if data['summary']['medium']:
        print("\n" + "~" * 70)
        print("~ MEDIUM – تحسينات أمنية")
        print("~" * 70)
        for item in data['summary']['medium']:
            print(f"\n  [{item['file']}:{item['line']}] {item['description']}")
            print(f"  العلاج: {item['remediation']}")
    
    print("\n" + "=" * 70)
    print("  النتيجة النهائية: راجع الـ CRITICAL و HIGH أولاً")
    print("  تم الفحص بواسطة: جموح (JUMOOH) – laravel_security_scanner.py v1.0")
    print("=" * 70)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("الاستخدام: python laravel_security_scanner.py <مسار_المشروع>")
        sys.exit(1)
    
    target = sys.argv[1]
    report = scan_project(target)
    
    # حفظ JSON
    json_path = os.path.join(target, "security_scan_report.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    
    print_report(report)
    print(f"\nتم حفظ التقرير بصيغة JSON في: {json_path}")