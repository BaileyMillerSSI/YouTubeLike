FROM microsoft/dotnet:2.1-aspnetcore-runtime AS base
WORKDIR /app
EXPOSE 11470
EXPOSE 44329

FROM microsoft/dotnet:2.1-sdk AS build
WORKDIR /src
COPY LoginAPI/LoginAPI.csproj LoginAPI/
RUN dotnet restore LoginAPI/LoginAPI.csproj
COPY . .
WORKDIR /src/LoginAPI
RUN dotnet build LoginAPI.csproj -c Release -o /app

FROM build AS publish
RUN dotnet publish LoginAPI.csproj -c Release -o /app

FROM base AS final
WORKDIR /app
COPY --from=publish /app .
ENTRYPOINT ["dotnet", "LoginAPI.dll"]
