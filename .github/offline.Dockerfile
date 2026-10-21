# 离线验证镜像（CI 的 `offline` job 用）。
#
# 为什么需要它：GitHub Actions 的 **job 容器**由运行器创建，且总是带一个
# user-defined network；再写 `container.options: --network none` 会得到
#   docker: conflicting options: cannot attach both user-defined and non-user-defined
#   network-modes
# （实测：run 39526291036 的 `Initialize containers` 步骤 exit 125）。
#
# 正确做法是**不把 job 放进容器**，而是在普通 runner 上用
# `docker run --network none` 起一个**嵌套**容器——`--network none` 只在
# `docker run` 这一层才合法。构建期需要网络（拉基础镜像），运行期完全无网络，
# 这正是要证明的那件事。
FROM python:3.12-slim

# 判定路径只依赖标准库；`tools/` 与 `tests/` 自己把仓库根塞进 sys.path
# （`conftest.py` / `offline_smoke.py` / `check_release.py`），因此**不需要 pip install**，
# 也就不需要在无网络时解析任何索引。
WORKDIR /work
COPY . /work

ENV PYTHONUTF8=1 \
    PYTHONDONTWRITEBYTECODE=1

CMD ["python", "tools/offline_smoke.py"]
