FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY frontend/frontend.csproj frontend/
RUN dotnet restore frontend/frontend.csproj

COPY frontend/ frontend/
WORKDIR /src/frontend
RUN dotnet publish -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app .

EXPOSE 80
ENV ASPNETCORE_URLS=http://+:80
ENTRYPOINT ["dotnet", "frontend.dll"]