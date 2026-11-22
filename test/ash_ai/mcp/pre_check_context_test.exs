# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.PreCheckContextTest do
  use ExUnit.Case, async: true
  import Plug.{Conn, Test}

  alias AshAi.Mcp.Router

  defmodule GrantedInContext do
    use Ash.Policy.SimpleCheck

    def match?(_actor, %{context: %{granted: true}}, _opts), do: true
    def match?(_actor, _context, _opts), do: false
    def describe(_opts), do: "the request context grants access"
  end

  defmodule Resource do
    use Ash.Resource,
      domain: AshAi.Mcp.PreCheckContextTest.Domain,
      authorizers: [Ash.Policy.Authorizer],
      data_layer: Ash.DataLayer.Ets

    ets do
      private? true
    end

    attributes do
      uuid_primary_key :id
    end

    actions do
      action :secret, :map do
        run fn _input, _context -> {:ok, %{value: "visible"}} end
      end
    end

    policies do
      policy action(:secret) do
        authorize_if GrantedInContext
      end
    end
  end

  defmodule Domain do
    use Ash.Domain, extensions: [AshAi]

    resources do
      resource Resource
    end

    tools do
      tool :secret, Resource, :secret
    end
  end

  @opts [actions: [{Resource, :*}], mcp_resources: []]

  describe "exposed_tools/1" do
    test "the pre-check sees the caller's context" do
      assert [%{name: :secret}] = AshAi.exposed_tools(@opts ++ [context: %{granted: true}])
      assert [] = AshAi.exposed_tools(@opts)
    end
  end

  describe "MCP router" do
    test "lists and calls a tool authorized by the connection's context" do
      assert ["secret"] = tool_names(%{granted: true})
      assert [] = tool_names(nil)

      result = call(%{granted: true}, "tools/call", %{"name" => "secret", "arguments" => %{}})
      assert result["isError"] == false
      assert result["structuredContent"] == %{"value" => "visible"}
    end
  end

  defp tool_names(context) do
    context
    |> call("tools/list", %{})
    |> Map.fetch!("tools")
    |> Enum.map(& &1["name"])
  end

  defp call(context, method, params) do
    session_id =
      context
      |> post(%{
        "jsonrpc" => "2.0",
        "id" => "init",
        "method" => "initialize",
        "params" => %{"protocolVersion" => "2025-06-18", "capabilities" => %{}}
      })
      |> get_resp_header("mcp-session-id")
      |> List.first()

    context
    |> post(
      %{"jsonrpc" => "2.0", "id" => method, "method" => method, "params" => params},
      session_id
    )
    |> Map.fetch!(:resp_body)
    |> Jason.decode!()
    |> Map.fetch!("result")
  end

  defp post(context, body, session_id \\ nil) do
    conn = conn(:post, "/", body)
    conn = if session_id, do: put_req_header(conn, "mcp-session-id", session_id), else: conn
    conn = if context, do: Ash.PlugHelpers.set_context(conn, context), else: conn
    Router.call(conn, @opts)
  end
end
