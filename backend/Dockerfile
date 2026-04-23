FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

COPY backend/backend.csproj backend/
RUN dotnet restore backend/backend.csproj

COPY backend/ backend/
WORKDIR /src/backend
RUN dotnet publish -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app .

# Копируем ТОЛЬКО датасет (модель обучится при старте)
COPY backend/legitphish.csv ./

EXPOSE 5000
ENV ASPNETCORE_URLS=http://+:5000
ENTRYPOINT ["dotnet", "backend.dll"]