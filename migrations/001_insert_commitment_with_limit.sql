-- Atomically enforce the per-user unrevealed-commitment limit and insert.
-- Replaces the check-then-insert done in two separate steps by /api/commit.

CREATE OR REPLACE FUNCTION public.insert_commitment_with_limit(
    p_commitment jsonb,
    p_limit      integer
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_user_id uuid := nullif(p_commitment->>'user_id', '')::uuid;
    v_count   integer;
BEGIN
    IF v_user_id IS NOT NULL THEN
        -- Serialize concurrent inserts for the same user for the rest of this
        -- transaction, so the count below can't go stale before the insert.
        PERFORM pg_advisory_xact_lock(hashtextextended(v_user_id::text, 0));

        SELECT count(*) INTO v_count
        FROM public.commitments
        WHERE user_id = v_user_id
          AND revealed = false;

        IF v_count >= p_limit THEN
            RETURN jsonb_build_object('inserted', false, 'unrevealed_count', v_count);
        END IF;
    END IF;

    INSERT INTO public.commitments (
        id, mac, nonce, context, domain, committed_at, user_id, visibility,
        on_wall, revealed, revealed_message, ots_status, ots_receipt,
        bitcoin_block, tsa_status, tsa_receipt
    ) VALUES (
        p_commitment->>'id',
        p_commitment->>'mac',
        p_commitment->>'nonce',
        p_commitment->>'context',
        p_commitment->>'domain',
        (p_commitment->>'committed_at')::timestamptz,
        v_user_id,
        p_commitment->>'visibility',
        (p_commitment->>'on_wall')::boolean,
        (p_commitment->>'revealed')::boolean,
        p_commitment->>'revealed_message',
        p_commitment->>'ots_status',
        p_commitment->>'ots_receipt',
        (p_commitment->>'bitcoin_block')::integer,
        p_commitment->>'tsa_status',
        p_commitment->>'tsa_receipt'
    );

    RETURN jsonb_build_object('inserted', true, 'unrevealed_count', coalesce(v_count, 0) + 1);
END;
$$;

-- Only the server (service key) may call this; never anon/authenticated clients.
REVOKE ALL ON FUNCTION public.insert_commitment_with_limit(jsonb, integer) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.insert_commitment_with_limit(jsonb, integer) TO service_role;
