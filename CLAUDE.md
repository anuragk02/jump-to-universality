# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This project implements the process of knowledge creation at an individual level, with the goal of making this system universal. The architecture consists of:
- **Data Layer**: Neo4j graph database on AuraDB
- **API Layer**: Go

## Session Workflow

At the start of every session:
1. Read ROADMAP.md to understand current project goals
2. Read LASTCHANGELOG.md for a summary of the previous session's changes

At the end of each session:
1. Append current session's changes to CHANGELOG.md (cumulative history)
2. Replace LASTCHANGELOG.md content with only the current session's changes

## Development Guidelines

- **Minimalist approach**: Only add or remove code to solve specific problems
- **Ask before assuming**: If instructions are unclear, request clarification rather than making assumptions that could lead to unnecessary changes
- **Avoid premature implementation**: Do not make assumptions that might lead to unnecessary code changes

## Architecture Notes

The system is being built with a clear separation between data storage (Neo4j) and the API layer (Go). When implementing features, maintain this architectural boundary.
