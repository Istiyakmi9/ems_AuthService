#See https://aka.ms/customizecontainer to learn how to customize your debug container and how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 80

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

ENV ASPNETCORE_ENVIRONMENT Production

COPY ["ems_AuthService/ems_AuthService.csproj", "ems_AuthService/"]
COPY ["ems_AuthServiceLayer/ems_AuthServiceLayer.csproj", "ems_AuthServiceLayer/"]
RUN dotnet restore "ems_AuthService/ems_AuthService.csproj"
COPY . .
WORKDIR "/src/ems_AuthService"
RUN dotnet build "ems_AuthService.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "ems_AuthService.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "ems_AuthService.dll"]