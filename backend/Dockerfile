FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY backend/backend.csproj backend/
RUN dotnet restore backend/backend.csproj
COPY backend/ backend/
WORKDIR /src/backend
RUN dotnet publish -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime

# 🔥 УСТАНОВКА ЗАВИСИМОСТЕЙ ДЛЯ LIGHTGBM
# libgomp1 нужен для OpenMP, libc6 и libstdc++6 - стандартные библиотеки C++
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libgomp1 \
    libc6 \
    libstdc++6 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /app .

# Копируем датасет, если он есть
COPY backend/legitphish.csv ./

EXPOSE 5000
ENV ASPNETCORE_URLS=http://+:5000
ENTRYPOINT ["dotnet", "backend.dll"]