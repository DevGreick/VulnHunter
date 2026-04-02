const I18N = {
    en: {
        nav_features: "Features",
        nav_quickstart: "Quick Start",
        nav_examples: "Examples",
        nav_ecosystems: "Ecosystems",
        nav_ai_triage: "AI Triage",
        tag_features: "&lt;features&gt;",
        tag_quickstart: "&lt;quickstart&gt;",
        tag_examples: "&lt;examples&gt;",
        tag_ecosystems: "&lt;ecosystems&gt;",
        tag_ai_triage: "&lt;ai-triage&gt;",
        tag_install: "&lt;install&gt;",
        hero_tagline: "Your dependencies have secrets. VulnHunter finds them.",
        hero_sub: "Offline vulnerability scanner with AI-powered triage.<br>No cloud, no API calls, no data leaves your machine.",
        get_started: "Get Started",
        view_github: "View on GitHub",
        ecosystems: "Ecosystems",
        file_formats: "File Formats",
        data_sources: "Data Sources",
        why_vulnhunter: "Why VulnHunter?",
        f_offline_title: "Offline First",
        f_offline_desc: "Your code never leaves your machine. All scanning happens locally against a pre-built vulnerability database. Air-gapped environments welcome.",
        f_ai_title: "AI-Powered Triage",
        f_ai_desc: "Local LLM analysis via Ollama. The AI reads your actual source code, correlates with CVE data, and tells you exactly where you're exposed.",
        f_multi_title: "Multi-Ecosystem",
        f_multi_desc: "Python, Node.js, Go, Rust, Java, PHP, Ruby — VulnHunter parses lockfiles, manifests, and dependency trees across 7 ecosystems and 15+ file formats.",
        f_sarif_title: "SARIF Export",
        f_sarif_desc: "Generate SARIF 2.1.0 reports for GitHub Code Scanning integration and VS Code SARIF Viewer. Drop findings directly into your workflow.",
        f_secure_title: "Secure by Design",
        f_secure_desc: "API keys stored in your OS keyring — never in plaintext. No secrets in logs, no data exfiltration. Built by a cybersecurity professional.",
        f_transitive_title: "Transitive Dependencies",
        f_transitive_desc: "Goes beyond direct deps. Integrates with pipdeptree, npm, mvn, composer, and go to scan the full dependency tree for hidden vulnerabilities.",
        quickstart_title: "Up and Running in 60 Seconds",
        examples_title: "Usage Examples",
        ex_basic_title: "Basic Scan",
        ex_basic_desc: "Point VulnHunter at any project directory. It auto-detects lockfiles and manifests across all supported ecosystems.",
        ex_ai_title: "AI-Powered Triage",
        ex_ai_desc_html: 'Add <code>--ai-triage</code> to let a local LLM analyze each vulnerability against your actual codebase. It identifies which CVEs are actually exploitable in your context.',
        ex_sarif_title: "SARIF Export",
        ex_sarif_desc: "Export results in SARIF 2.1.0 format for GitHub Code Scanning or VS Code SARIF Viewer. Integrates directly into your CI/CD pipeline.",
        ex_db_title: "Database Management",
        ex_db_desc: "Download the pre-built database from GitHub Releases or build your own from OSV and NVD sources. Auto-updated weekly via GitHub Actions.",
        ex_config_title: "Configuration",
        ex_config_desc: "Manage settings, API keys, and AI preferences. NVD keys are stored securely in your OS keyring — never in plaintext config files.",
        ex_cicd_title: "CI/CD Integration",
        ex_cicd_desc: "Add VulnHunter to your GitHub Actions pipeline. Fail builds on critical vulnerabilities and upload SARIF to GitHub Security tab.",
        eco_title: "Supported Ecosystems",
        eco_th1: "Ecosystem",
        eco_th2: "Files Detected",
        eco_th3: "Transitive Deps",
        ai_section_title: "AI-Powered Vulnerability Triage",
        ai_how: "How It Works",
        ai_step1_title: "Scan",
        ai_step1_desc: "VulnHunter identifies vulnerable dependencies in your project.",
        ai_step2_title: "Analyze",
        ai_step2_desc: "The local LLM reads your source code and correlates it with CVE details.",
        ai_step3_title: "Triage",
        ai_step3_desc: "Each vulnerability gets a contextual risk assessment: is it actually reachable in your code?",
        ai_step4_title: "Prioritize",
        ai_step4_desc: "Focus on what matters. Stop wasting time on CVEs that don't affect you.",
        ai_rec_models: "Recommended Models",
        ai_model_phi3: "Basic triage. Low resource usage.",
        ai_model_mistral: "Best balance of speed and accuracy.",
        ai_model_llama3: "Deep analysis. Best results.",
        nav_sdk: "SDK",
        tag_sdk: "&lt;SDK&gt;",
        sdk_section_title: "Python SDK",
        sdk_intro: "Use VulnHunter as a Python library to integrate vulnerability scanning into your own tools and workflows.",
        sdk_scan_title: "Scan Dependencies",
        sdk_scan_desc: "The <code>analyze()</code> function takes a database and a list of dependencies, returning a <code>ScanResult</code> with all matched vulnerabilities sorted by severity.",
        sdk_triage_title: "AI Triage",
        sdk_triage_desc: "The <code>TriageEngine</code> sends each vulnerability to a local Ollama LLM along with code references found by <code>CodeAnalyzer</code>, returning contextual risk assessments.",
        sdk_export_title: "Export Reports",
        sdk_export_desc: "Use <code>render_xlsx()</code> to generate styled Excel reports, or access the <code>ScanResult</code> model directly for custom integrations.",
        sdk_full_link: "Full SDK Documentation (Markdown)",
        install_title: "Installation",
        install_pypi: "PyPI (recommended)",
        install_uv: "With uv (faster)",
        install_source: "From Source",
        prereqs_title: "Prerequisites",
        prereq_python_html: "<strong>Python 3.8+</strong> — Required",
        prereq_ollama_html: '<strong>Ollama</strong> — Optional, for AI triage. <a href="https://ollama.com/download" target="_blank" rel="noopener">Download here</a>',
        prereq_nvd_html: '<strong>NVD API Key</strong> — Optional, speeds up database updates. <a href="https://nvd.nist.gov/developers/request-an-api-key" target="_blank" rel="noopener">Free key</a>',
        footer_built_html: 'Built with security in mind by <a href="https://github.com/DevGreick" target="_blank" rel="noopener">DevGreick</a>',
    },
    pt: {
        nav_features: "Funcionalidades",
        nav_quickstart: "Inicio Rapido",
        nav_examples: "Exemplos",
        nav_ecosystems: "Ecossistemas",
        nav_ai_triage: "Triagem IA",
        tag_features: "&lt;funcionalidades&gt;",
        tag_quickstart: "&lt;inicio-rapido&gt;",
        tag_examples: "&lt;exemplos&gt;",
        tag_ecosystems: "&lt;ecossistemas&gt;",
        tag_ai_triage: "&lt;triagem-ia&gt;",
        tag_install: "&lt;instalacao&gt;",
        hero_tagline: "Suas dependencias guardam segredos. O VulnHunter encontra.",
        hero_sub: "Scanner offline de vulnerabilidades com triagem por IA.<br>Sem cloud, sem chamadas de API, nenhum dado sai da sua maquina.",
        get_started: "Comecar",
        view_github: "Ver no GitHub",
        ecosystems: "Ecossistemas",
        file_formats: "Formatos",
        data_sources: "Fontes de Dados",
        why_vulnhunter: "Por que VulnHunter?",
        f_offline_title: "100% Offline",
        f_offline_desc: "Seu codigo nunca sai da sua maquina. Todo o scan acontece localmente contra um banco de vulnerabilidades pre-construido. Ambientes air-gapped sao bem-vindos.",
        f_ai_title: "Triagem com IA",
        f_ai_desc: "Analise local via Ollama. A IA le seu codigo-fonte real, correlaciona com dados de CVE e mostra exatamente onde voce esta exposto.",
        f_multi_title: "Multi-Ecossistema",
        f_multi_desc: "Python, Node.js, Go, Rust, Java, PHP, Ruby — o VulnHunter analisa lockfiles, manifests e arvores de dependencias em 7 ecossistemas e 15+ formatos.",
        f_sarif_title: "Export SARIF",
        f_sarif_desc: "Gere relatorios SARIF 2.1.0 para integracao com GitHub Code Scanning e VS Code SARIF Viewer. Encaixe os resultados direto no seu workflow.",
        f_secure_title: "Seguro por Design",
        f_secure_desc: "Chaves de API armazenadas no keyring do sistema — nunca em texto puro. Sem segredos em logs, sem exfiltracao de dados. Feito por um profissional de ciberseguranca.",
        f_transitive_title: "Dependencias Transitivas",
        f_transitive_desc: "Vai alem das deps diretas. Integra com pipdeptree, npm, mvn, composer e go para escanear toda a arvore de dependencias em busca de vulnerabilidades ocultas.",
        quickstart_title: "Funcionando em 60 Segundos",
        examples_title: "Exemplos de Uso",
        ex_basic_title: "Scan Basico",
        ex_basic_desc: "Aponte o VulnHunter para qualquer diretorio de projeto. Ele detecta automaticamente lockfiles e manifests de todos os ecossistemas suportados.",
        ex_ai_title: "Triagem com IA",
        ex_ai_desc_html: 'Adicione <code>--ai-triage</code> para que uma LLM local analise cada vulnerabilidade contra seu codigo real. Identifica quais CVEs sao realmente exploraveis no seu contexto.',
        ex_sarif_title: "Export SARIF",
        ex_sarif_desc: "Exporte resultados no formato SARIF 2.1.0 para GitHub Code Scanning ou VS Code SARIF Viewer. Integra direto no seu pipeline de CI/CD.",
        ex_db_title: "Gerenciamento do Banco",
        ex_db_desc: "Baixe o banco pre-construido do GitHub Releases ou construa o seu a partir das fontes OSV e NVD. Atualizado semanalmente via GitHub Actions.",
        ex_config_title: "Configuracao",
        ex_config_desc: "Gerencie configuracoes, chaves de API e preferencias de IA. Chaves NVD sao armazenadas com seguranca no keyring do sistema — nunca em arquivos de config.",
        ex_cicd_title: "Integracao CI/CD",
        ex_cicd_desc: "Adicione o VulnHunter ao seu pipeline do GitHub Actions. Bloqueie builds com vulnerabilidades criticas e envie SARIF para a aba Security do GitHub.",
        eco_title: "Ecossistemas Suportados",
        eco_th1: "Ecossistema",
        eco_th2: "Arquivos Detectados",
        eco_th3: "Deps Transitivas",
        ai_section_title: "Triagem de Vulnerabilidades com IA",
        ai_how: "Como Funciona",
        ai_step1_title: "Scan",
        ai_step1_desc: "O VulnHunter identifica dependencias vulneraveis no seu projeto.",
        ai_step2_title: "Analise",
        ai_step2_desc: "A LLM local le seu codigo-fonte e correlaciona com os detalhes da CVE.",
        ai_step3_title: "Triagem",
        ai_step3_desc: "Cada vulnerabilidade recebe uma avaliacao contextual de risco: ela e realmente acessivel no seu codigo?",
        ai_step4_title: "Priorize",
        ai_step4_desc: "Foque no que importa. Pare de perder tempo com CVEs que nao te afetam.",
        ai_rec_models: "Modelos Recomendados",
        ai_model_phi3: "Triagem basica. Baixo consumo de recursos.",
        ai_model_mistral: "Melhor equilibrio entre velocidade e precisao.",
        ai_model_llama3: "Analise profunda. Melhores resultados.",
        nav_sdk: "SDK",
        tag_sdk: "&lt;SDK&gt;",
        sdk_section_title: "Python SDK",
        sdk_intro: "Use o VulnHunter como biblioteca Python para integrar escaneamento de vulnerabilidades nas suas ferramentas e workflows.",
        sdk_scan_title: "Escanear Dependencias",
        sdk_scan_desc: "A funcao <code>analyze()</code> recebe um banco de dados e uma lista de dependencias, retornando um <code>ScanResult</code> com todas as vulnerabilidades encontradas ordenadas por severidade.",
        sdk_triage_title: "Triagem IA",
        sdk_triage_desc: "O <code>TriageEngine</code> envia cada vulnerabilidade para uma LLM local via Ollama junto com referencias de codigo encontradas pelo <code>CodeAnalyzer</code>, retornando avaliacoes contextuais de risco.",
        sdk_export_title: "Exportar Relatorios",
        sdk_export_desc: "Use <code>render_xlsx()</code> para gerar relatorios Excel estilizados, ou acesse o modelo <code>ScanResult</code> diretamente para integracoes customizadas.",
        sdk_full_link: "Documentacao Completa do SDK (Markdown)",
        install_title: "Instalacao",
        install_pypi: "PyPI (recomendado)",
        install_uv: "Com uv (mais rapido)",
        install_source: "Pelo Codigo-Fonte",
        prereqs_title: "Pre-requisitos",
        prereq_python_html: "<strong>Python 3.8+</strong> — Obrigatorio",
        prereq_ollama_html: '<strong>Ollama</strong> — Opcional, para triagem com IA. <a href="https://ollama.com/download" target="_blank" rel="noopener">Baixe aqui</a>',
        prereq_nvd_html: '<strong>NVD API Key</strong> — Opcional, acelera atualizacoes do banco. <a href="https://nvd.nist.gov/developers/request-an-api-key" target="_blank" rel="noopener">Key gratuita</a>',
        footer_built_html: 'Feito com seguranca em mente por <a href="https://github.com/DevGreick" target="_blank" rel="noopener">DevGreick</a>',
    },
};

window._vhLang = "en";

function applyLang(lang) {
    window._vhLang = lang;
    const dict = I18N[lang];
    if (!dict) return;
    document.querySelectorAll("[data-i18n]").forEach((el) => {
        const key = el.getAttribute("data-i18n");
        if (!dict[key]) return;
        if (key.endsWith("_html")) {
            el.innerHTML = dict[key];
        } else {
            el.innerHTML = dict[key];
        }
    });
    const btn = document.getElementById("langToggle");
    if (btn) btn.textContent = lang === "en" ? "EN" : "PT-BR";
    document.documentElement.lang = lang === "pt" ? "pt-BR" : "en";
    try { localStorage.setItem("vulnhunter-lang", lang); } catch (_) {}
}

function initLang() {
    const btn = document.getElementById("langToggle");
    if (!btn) return;

    let saved = null;
    try { saved = localStorage.getItem("vulnhunter-lang"); } catch (_) {}
    if (saved && I18N[saved]) {
        applyLang(saved);
    } else {
        const browserLang = navigator.language || "";
        if (browserLang.startsWith("pt")) applyLang("pt");
    }

    btn.addEventListener("click", () => {
        applyLang(window._vhLang === "en" ? "pt" : "en");
    });
}

document.addEventListener("DOMContentLoaded", () => {
    initParticles();
    initReveal();
    initNavbar();
    initCopyButtons();
    initCountUp();
    initNavToggle();
    initLang();
});

function initParticles() {
    const canvas = document.getElementById("particles");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    let w, h, particles;
    const PARTICLE_COUNT = 80;
    const MAX_DIST = 150;

    function resize() {
        w = canvas.width = window.innerWidth;
        h = canvas.height = window.innerHeight;
    }

    function createParticles() {
        particles = [];
        for (let i = 0; i < PARTICLE_COUNT; i++) {
            particles.push({
                x: Math.random() * w,
                y: Math.random() * h,
                vx: (Math.random() - 0.5) * 0.4,
                vy: (Math.random() - 0.5) * 0.4,
                r: Math.random() * 1.5 + 0.5,
            });
        }
    }

    function draw() {
        ctx.clearRect(0, 0, w, h);

        for (let i = 0; i < particles.length; i++) {
            const p = particles[i];
            p.x += p.vx;
            p.y += p.vy;

            if (p.x < 0) p.x = w;
            if (p.x > w) p.x = 0;
            if (p.y < 0) p.y = h;
            if (p.y > h) p.y = 0;

            ctx.beginPath();
            ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
            ctx.fillStyle = "rgba(0, 229, 255, 0.4)";
            ctx.fill();

            for (let j = i + 1; j < particles.length; j++) {
                const p2 = particles[j];
                const dx = p.x - p2.x;
                const dy = p.y - p2.y;
                const dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < MAX_DIST) {
                    const alpha = (1 - dist / MAX_DIST) * 0.15;
                    ctx.beginPath();
                    ctx.moveTo(p.x, p.y);
                    ctx.lineTo(p2.x, p2.y);
                    ctx.strokeStyle = `rgba(0, 229, 255, ${alpha})`;
                    ctx.lineWidth = 0.5;
                    ctx.stroke();
                }
            }
        }

        requestAnimationFrame(draw);
    }

    resize();
    createParticles();
    draw();

    window.addEventListener("resize", () => {
        resize();
        createParticles();
    });
}

function initReveal() {
    const elements = document.querySelectorAll(".reveal");
    if (!elements.length) return;

    const observer = new IntersectionObserver(
        (entries) => {
            entries.forEach((entry) => {
                if (entry.isIntersecting) {
                    entry.target.classList.add("visible");
                }
            });
        },
        { threshold: 0.1, rootMargin: "0px 0px -40px 0px" }
    );

    elements.forEach((el) => observer.observe(el));
}

function initNavbar() {
    const navbar = document.getElementById("navbar");
    if (!navbar) return;

    let ticking = false;
    window.addEventListener("scroll", () => {
        if (!ticking) {
            requestAnimationFrame(() => {
                if (window.scrollY > 50) {
                    navbar.classList.add("scrolled");
                } else {
                    navbar.classList.remove("scrolled");
                }
                ticking = false;
            });
            ticking = true;
        }
    });
}

function initCopyButtons() {
    document.querySelectorAll(".copy-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
            const text = btn.getAttribute("data-copy");
            if (!text) return;

            navigator.clipboard.writeText(text).then(() => {
                const original = btn.textContent;
                btn.textContent = "Copied!";
                btn.classList.add("copied");
                setTimeout(() => {
                    btn.textContent = original;
                    btn.classList.remove("copied");
                }, 2000);
            });
        });
    });
}

function initCountUp() {
    const counters = document.querySelectorAll("[data-count]");
    if (!counters.length) return;

    const observer = new IntersectionObserver(
        (entries) => {
            entries.forEach((entry) => {
                if (entry.isIntersecting) {
                    const el = entry.target;
                    const target = parseInt(el.getAttribute("data-count"), 10);
                    if (isNaN(target)) return;

                    let current = 0;
                    const step = Math.max(1, Math.floor(target / 30));
                    const interval = setInterval(() => {
                        current += step;
                        if (current >= target) {
                            current = target;
                            clearInterval(interval);
                        }
                        el.textContent = current;
                    }, 40);

                    observer.unobserve(el);
                }
            });
        },
        { threshold: 0.5 }
    );

    counters.forEach((el) => observer.observe(el));
}

function initNavToggle() {
    const toggle = document.getElementById("navToggle");
    const links = document.getElementById("navLinks");
    if (!toggle || !links) return;

    toggle.addEventListener("click", () => {
        links.classList.toggle("open");
    });

    links.querySelectorAll("a").forEach((a) => {
        a.addEventListener("click", () => {
            links.classList.remove("open");
        });
    });
}
