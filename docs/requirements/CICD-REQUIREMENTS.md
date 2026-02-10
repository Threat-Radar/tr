# CI/CD Pipeline Requirements - Issue #120

## 🎯 Goal
Enable rapid delivery: push to main → auto build/test → Paul downloads latest build

---

## 📋 Core Requirements

### 1. Automated Build Pipeline
**Trigger:** Every push to `main` branch
**Actions:**
- Run `pytest` (full test suite)
- Build Python wheel (`.whl`)
- Build source distribution (`.tar.gz`)
- Generate version number (auto-increment or from git tag)
- Create GitHub Release with artifacts

**Success Criteria:**
- ✅ Build completes in < 5 minutes
- ✅ Tests must pass for release to be created
- ✅ Artifacts are downloadable

---

### 2. Public Status Page
**URL:** `https://threat-radar.github.io/tr` (GitHub Pages)

**Content (Simple):**
```
Threat-Radar
Vulnerability Analysis Platform

Latest Release: v0.2.1
Status: ✅ Passing (45/45 tests)
Built: 2026-02-10 06:25 UTC

[Download .whl] [Download .tar.gz] [View on GitHub]

Installation:
pip install threat-radar-0.2.1-py3-none-any.whl
```

**Requirements:**
- ✅ Auto-updates on every build
- ✅ Shows pass/fail status
- ✅ Direct download links
- ✅ Build timestamp
- ✅ Test count (X/Y passed)
- ✅ Version number prominent

---

### 3. Version Management
**Strategy:** Use git tags for releases

**Format:** `v0.2.x` (semantic versioning)
- Manual tagging: `git tag v0.2.1 && git push --tags`
- Or auto-increment patch version on main push

**Question for Paul:** Manual tags or auto-increment?

---

## 🛠️ Technical Approach

### Option A: GitHub Actions + GitHub Pages (Recommended)
**Why:** Free, integrated, simple

**Components:**
1. `.github/workflows/build.yml` - Build/test on push
2. `.github/workflows/deploy-status.yml` - Update status page
3. `docs/index.html` - Simple status page (gh-pages branch)
4. GitHub Releases - Host downloadable artifacts

**Pros:** All-in-one, free, no external deps
**Cons:** Basic UI

### Option B: GitHub Actions + Netlify
**Why:** Prettier status page

**Pros:** Better UI, easy deploys
**Cons:** Another service to manage

---

## ✅ Acceptance Criteria

**Must Have:**
- [ ] Push to main triggers build automatically
- [ ] All tests run (pytest)
- [ ] Build artifacts created (.whl, .tar.gz)
- [ ] Status page shows latest build info
- [ ] Download links work
- [ ] Build time < 5 minutes
- [ ] Failed builds don't create releases

**Nice to Have:**
- [ ] Build status badge in README
- [ ] Docker image built (optional)
- [ ] Email notification on failure (optional)

---

## 🎯 Simple Start (MVP)

**Phase 1 (Do First):**
1. GitHub Actions workflow for build/test
2. Create GitHub Release with artifacts
3. Basic HTML status page (1 page, no fancy CSS)
4. Auto-deploy status page to gh-pages

**Phase 2 (Later):**
- Prettier status page
- Build history
- Test coverage reports
- Performance metrics

---

## 📊 Test Scenarios

1. **Happy Path:** Push to main → tests pass → release created → status page updates
2. **Test Failure:** Push to main → tests fail → no release → status shows failure
3. **Manual Download:** User visits status page → clicks download → gets .whl file → `pip install` works

---

## 🔧 Implementation Estimate
**Time:** 1-2 hours for Phase 1
**Files to Create:**
- `.github/workflows/build.yml` (GitHub Actions config)
- `docs/index.html` (status page)
- Update `pyproject.toml` (version management)

---

## ❓ Questions for Paul

1. **Versioning:** Manual git tags or auto-increment patch version?
2. **Status Page:** GitHub Pages (simple) or Netlify (prettier)?
3. **Artifacts:** Just .whl + .tar.gz, or also Docker image?
4. **Test on push:** Only to `main`, or also feature branches?

---

## 🚀 Next Steps (After Approval)

1. Paul reviews/approves this requirements doc
2. Paul answers questions above
3. I create `feature/cicd-pipeline` branch
4. Implement Phase 1 (MVP)
5. Test locally
6. Push branch → demo to Paul
7. Iterate based on feedback
8. Merge with approval

---

**Ready for your input!** 🎯
