/// @file
/// @author rfree (current maintainer/user in monero.cc project - most of code is from CryptoNote)
/// @brief This is the original cryptonote protocol network-events handler, modified by us

// Copyright (c) 2020, Ryo Currency Project
// Portions copyright (c) 2014-2018, The Monero Project
//
// Portions of this file are available under BSD-3 license. Please see ORIGINAL-LICENSE for details
// All rights reserved.
//
// Authors and copyright holders give permission for following:
//
// 1. Redistribution and use in source and binary forms WITHOUT modification.
//
// 2. Modification of the source form for your own personal use.
//
// As long as the following conditions are met:
//
// 3. You must not distribute modified copies of the work to third parties. This includes
//    posting the work online, or hosting copies of the modified work for download.
//
// 4. Any derivative version of this work is also covered by this license, including point 8.
//
// 5. Neither the name of the copyright holders nor the names of the authors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// 6. You agree that this licence is governed by and shall be construed in accordance
//    with the laws of England and Wales.
//
// 7. You agree to submit all disputes arising out of or in connection with this licence
//    to the exclusive jurisdiction of the Courts of England and Wales.
//
// Authors and copyright holders agree that:
//
// 8. This licence expires and the work covered by it is released into the
//    public domain on 1st of February 2021
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

// (may contain code and/or modifications by other developers)
// developer rfree: this code is caller of our new network code, and is modded; e.g. for rate limiting

//IGNORE
#include <boost/interprocess/detail/atomic.hpp>
#include <ctime>
#include <list>

#include "cryptonote_basic/verification_context.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "net/network_throttle-detail.hpp"
#include "profile_tools.h"
#include <common/command_line.h>
#include "cryptonote_core/cryptonote_core.h"
#include "common/gulps.hpp"
#include "common/perf_timer.h"

#define context_str std::string("[" + epee::net_utils::print_connection_context_short(context) + "]")

#define GULPS_P2P_MESSAGE(...) GULPS_OUTPUTF(gulps::OUT_USER_0, gulps::LEVEL_INFO, "p2p", gulps_minor_cat::c_str(), gulps::COLOR_WHITE, __VA_ARGS__)

#define BLOCK_QUEUE_NSPANS_THRESHOLD 10                     // chunks of N blocks
#define BLOCK_QUEUE_SIZE_THRESHOLD (100 * 1024 * 1024)		// MB
#define BLOCK_QUEUE_FORCE_DOWNLOAD_NEAR_BLOCKS 1000
#define REQUEST_NEXT_SCHEDULED_SPAN_THRESHOLD (5 * 1000000) // microseconds
#define IDLE_PEER_KICK_TIME (240 * 1000000)					// microseconds
#define NON_RESPONSIVE_PEER_KICK_TIME (20 * 1000000)		// microseconds
#define PASSIVE_PEER_KICK_TIME (60 * 1000000)				// microseconds
#define REQUEST_NEXT_SCHEDULED_SPAN_THRESHOLD_STANDBY (5 * 1000000) // microseconds
#define DROP_ON_SYNC_WEDGE_THRESHOLD (30 * 1000000000ull) 	// nanoseconds
#define LAST_ACTIVITY_STALL_THRESHOLD (2.0f)				// seconds

namespace cryptonote
{

//-----------------------------------------------------------------------------------------------------------------------
template <class t_core>
t_cryptonote_protocol_handler<t_core>::t_cryptonote_protocol_handler(t_core &rcore, nodetool::i_p2p_endpoint<connection_context> *p_net_layout, bool offline) : m_core(rcore),
																																								m_p2p(p_net_layout),
																																								m_syncronized_connections_count(0),
																																								m_synchronized(offline),
																																								m_stopping(false)

{
	if(!m_p2p)
		m_p2p = &m_p2p_stub;
}
//-----------------------------------------------------------------------------------------------------------------------
template <class t_core>
bool t_cryptonote_protocol_handler<t_core>::init(const boost::program_options::variables_map &vm)
{
    m_sync_timer.pause();
    m_sync_timer.reset();
    m_add_timer.pause();
    m_add_timer.reset();
    m_last_add_end_time = 0;
    m_sync_download_chain_size = 0;
	m_sync_download_objects_size = 0;
    m_block_download_max_size = command_line::get_arg(vm, arg_block_download_max_size);
	return true;
}
//------------------------------------------------------------------------------------------------------------------------
template <class t_core>
bool t_cryptonote_protocol_handler<t_core>::deinit()
{
	return true;
}
//------------------------------------------------------------------------------------------------------------------------
template <class t_core>
void t_cryptonote_protocol_handler<t_core>::set_p2p_endpoint(nodetool::i_p2p_endpoint<connection_context> *p2p)
{
	if(p2p)
		m_p2p = p2p;
	else
		m_p2p = &m_p2p_stub;
}
//------------------------------------------------------------------------------------------------------------------------
template <class t_core>
bool t_cryptonote_protocol_handler<t_core>::on_callback(cryptonote_connection_context &context)
{
	GULPS_LOG_L1(context_str, " callback fired");
	GULPS_CHECK_AND_ASSERT_MES_CONTEXT(context.m_callback_request_count > 0, false, "false callback fired, but context.m_callback_request_count=", context.m_callback_request_count);
	--context.m_callback_request_count;

	uint32_t notified = true;
	if (context.m_idle_peer_notification.compare_exchange_strong(notified, not notified))
	{
		if (context.m_state == cryptonote_connection_context::state_synchronizing && context.m_last_request_time != boost::date_time::not_a_date_time)
		{
			const boost::posix_time::ptime now = boost::posix_time::microsec_clock::universal_time();
			const boost::posix_time::time_duration dt = now - context.m_last_request_time;
			const auto ms = dt.total_microseconds();
			if (ms > IDLE_PEER_KICK_TIME || (context.m_expect_response && ms > NON_RESPONSIVE_PEER_KICK_TIME))
			{
				if (context.m_score-- >= 0)
				{
					GULPS_LOG_L1("{} kicking idle peer, last update {} seconds ago, expecting {}", context_str, (dt.total_microseconds() / 1.e6), (int)context.m_expect_response);
					context.m_last_request_time = boost::date_time::not_a_date_time;
					context.m_expect_response = 0;
					context.m_expect_height = 0;
					context.m_requested_objects.clear();
					context.m_state = cryptonote_connection_context::state_standby; // we'll go back to adding, then (if we can't), download
				}
				else
				{
					GULPS_LOG_L1(context_str, "dropping idle peer with negative score");
					drop_connection_with_score(context, context.m_expect_response == 0 ? 1 : 5, false);
					return false;
				}
			}
		}
	}

	notified = true;
	if (context.m_new_stripe_notification.compare_exchange_strong(notified, not notified))
	{
		if (context.m_state == cryptonote_connection_context::state_normal)
			context.m_state = cryptonote_connection_context::state_synchronizing;
	}

	if(context.m_state == cryptonote_connection_context::state_synchronizing && context.m_last_request_time == boost::posix_time::not_a_date_time)
		
	{
		NOTIFY_REQUEST_CHAIN::request r = {};
		context.m_needed_objects.clear();
		context.m_expect_height = m_core.get_current_blockchain_height();
		m_core.get_short_chain_history(r.block_ids);
		handler_request_blocks_history( r.block_ids ); // change the limit(?), sleep(?)
		context.m_last_request_time = boost::posix_time::microsec_clock::universal_time();
		context.m_expect_response = NOTIFY_RESPONSE_CHAIN_ENTRY::ID;
		GULPS_P2P_MESSAGE("-->>NOTIFY_REQUEST_CHAIN: m_block_ids.size()={}", r.block_ids.size() );
		post_notify<NOTIFY_REQUEST_CHAIN>(r, context);
		GULPS_LOG_L1("requesting chain");
	}
	else if(context.m_state == cryptonote_connection_context::state_standby)
	{
		context.m_state = cryptonote_connection_context::state_synchronizing;
		try_add_next_blocks(context);
	}

	return true;
}
//------------------------------------------------------------------------------------------------------------------------
template <class t_core>
bool t_cryptonote_protocol_handler<t_core>::get_stat_info(core_stat_info &stat_inf)
{
	return m_core.get_stat_info(stat_inf);
}
//------------------------------------------------------------------------------------------------------------------------
template <class t_core>
void t_cryptonote_protocol_handler<t_core>::log_connections()
{
	std::stringstream ss;
	ss.precision(1);

	double down_sum = 0.0;
	double down_curr_sum = 0.0;
	double up_sum = 0.0;
	double up_curr_sum = 0.0;

	ss << std::setw(30) << std::left << "Remote Host"
	   << std::setw(20) << "Peer id"
	   << std::setw(20) << "Support Flags"
	   << std::setw(30) << "Recv/Sent (inactive,sec)"
	   << std::setw(25) << "State"
	   << std::setw(20) << "Livetime(sec)"
	   << std::setw(12) << "Down (kB/s)"
	   << std::setw(14) << "Down(now)"
	   << std::setw(10) << "Up (kB/s)"
	   << std::setw(13) << "Up(now)"
	   << "\n";

	m_p2p->for_each_connection([&](const connection_context &cntxt, nodetool::peerid_type peer_id, uint32_t support_flags) {
		bool local_ip = cntxt.m_remote_address.is_local();
		auto connection_time = time(NULL) - cntxt.m_started;
		ss << std::setw(30) << std::left << std::string(cntxt.m_is_income ? " [INC]" : "[OUT]") + cntxt.m_remote_address.str()
		   << std::setw(20) << std::hex << peer_id
		   << std::setw(20) << std::hex << support_flags
		   << std::setw(30) << std::to_string(cntxt.m_recv_cnt) + "(" + std::to_string(time(NULL) - cntxt.m_last_recv) + ")" + "/" + std::to_string(cntxt.m_send_cnt) + "(" + std::to_string(time(NULL) - cntxt.m_last_send) + ")"
		   << std::setw(25) << get_protocol_state_string(cntxt.m_state)
		   << std::setw(20) << std::to_string(time(NULL) - cntxt.m_started)
		   << std::setw(12) << std::fixed << (connection_time == 0 ? 0.0 : cntxt.m_recv_cnt / connection_time / 1024)
		   << std::setw(14) << std::fixed << cntxt.m_current_speed_down / 1024
		   << std::setw(10) << std::fixed << (connection_time == 0 ? 0.0 : cntxt.m_send_cnt / connection_time / 1024)
		   << std::setw(13) << std::fixed << cntxt.m_current_speed_up / 1024
		   << (local_ip ? "[LAN]" : "")
		   << std::left << (cntxt.m_remote_address.is_loopback() ? "[LOCALHOST]" : "") // 127.0.0.1
		   << "\n";

		if(connection_time > 1)
		{
			down_sum += (cntxt.m_recv_cnt / connection_time / 1024);
			up_sum += (cntxt.m_send_cnt / connection_time / 1024);
		}

		down_curr_sum += (cntxt.m_current_speed_down / 1024);
		up_curr_sum += (cntxt.m_current_speed_up / 1024);

		return true;
	});
	ss << "\n"
	   << std::setw(125) << " "
	   << std::setw(12) << down_sum
	   << std::setw(14) << down_curr_sum
	   << std::setw(10) << up_sum
	   << std::setw(13) << up_curr_sum
	   << "\n";
		GULPS_PRINT("Connections:\n", ss.str());
}
//------------------------------------------------------------------------------------------------------------------------
// Returns a list of connection_info objects describing each open p2p connection
//------------------------------------------------------------------------------------------------------------------------
template <class t_core>
std::list<connection_info> t_cryptonote_protocol_handler<t_core>::get_connections()
{
	std::list<connection_info> connections;

	m_p2p->for_each_connection([&](const connection_context &cntxt, nodetool::peerid_type peer_id, uint32_t support_flags) {
		connection_info cnx;
		auto timestamp = time(NULL);

		cnx.incoming = cntxt.m_is_income ? true : false;

		cnx.address = cntxt.m_remote_address.str();
		cnx.host = cntxt.m_remote_address.host_str();
		cnx.ip = "";
		cnx.port = "";
		if(cntxt.m_remote_address.get_type_id() == epee::net_utils::ipv4_network_address::ID)
		{
			cnx.ip = cnx.host;
			cnx.port = std::to_string(cntxt.m_remote_address.as<epee::net_utils::ipv4_network_address>().port());
		}

		std::stringstream peer_id_str;
		peer_id_str << std::hex << std::setw(16) << peer_id;
		peer_id_str >> cnx.peer_id;

		cnx.support_flags = support_flags;

		cnx.recv_count = cntxt.m_recv_cnt;
		cnx.recv_idle_time = timestamp - std::max(cntxt.m_started, cntxt.m_last_recv);

		cnx.send_count = cntxt.m_send_cnt;
		cnx.send_idle_time = timestamp - std::max(cntxt.m_started, cntxt.m_last_send);

		cnx.state = get_protocol_state_string(cntxt.m_state);

		cnx.live_time = timestamp - cntxt.m_started;

		cnx.localhost = cntxt.m_remote_address.is_loopback();
		cnx.local_ip = cntxt.m_remote_address.is_local();

		auto connection_time = time(NULL) - cntxt.m_started;
		if(connection_time == 0)
		{
			cnx.avg_download = 0;
			cnx.avg_upload = 0;
		}

		else
		{
			cnx.avg_download = cntxt.m_recv_cnt / connection_time / 1024;
			cnx.avg_upload = cntxt.m_send_cnt / connection_time / 1024;
		}

		cnx.current_download = cntxt.m_current_speed_down / 1024;
		cnx.current_upload = cntxt.m_current_speed_up / 1024;

		cnx.connection_id = epee::string_tools::pod_to_hex(cntxt.m_connection_id);

		cnx.height = cntxt.m_remote_blockchain_height;

		connections.push_back(cnx);

		return true;
	});

	return connections;
}
//------------------------------------------------------------------------------------------------------------------------
template <class t_core>
bool t_cryptonote_protocol_handler<t_core>::process_payload_sync_data(const CORE_SYNC_DATA &hshd, cryptonote_connection_context &context, bool is_inital)
{
	if(context.m_state == cryptonote_connection_context::state_before_handshake && !is_inital)
		return true;

	if(context.m_state == cryptonote_connection_context::state_synchronizing)
		return true;

	// from v6, if the peer advertises a top block version, reject if it's not what it should be (will only work if no voting)
	if(hshd.current_height > 0)
	{
		const uint8_t version = m_core.get_ideal_hard_fork_version(hshd.current_height - 1);
		if(version >= 6 && version != hshd.top_version)
		{
			if(version < hshd.top_version && version == m_core.get_ideal_hard_fork_version())
				GULPSF_CAT_WARN("global", "{} peer claims higher version that we think ({} for {} instead of {}) - we may be forked from the network and a software upgrade may be needed", context_str, (unsigned)hshd.top_version, (hshd.current_height - 1), (unsigned)version);
			return false;
		}
	}

	if (hshd.current_height < context.m_remote_blockchain_height)
	{
		GULPSF_LOG_L1("{} Claims {}, claimed {} before", context_str, hshd.current_height, context.m_remote_blockchain_height);
		hit_score(context, 1);
	}

	context.m_remote_blockchain_height = hshd.current_height;

	uint64_t target = m_core.get_target_blockchain_height();
	if(target == 0)
		target = m_core.get_current_blockchain_height();

	if(m_core.have_block(hshd.top_id))
	{
		context.m_state = cryptonote_connection_context::state_normal;
		if(is_inital && target == m_core.get_current_blockchain_height())
			on_connection_synchronized();
		return true;
	}

	if(hshd.current_height > target)
	{
		/* As I don't know if accessing hshd from core could be a good practice,
    I prefer pushing target height to the core at the same time it is pushed to the user.
    Nz. */
		m_core.set_target_blockchain_height((hshd.current_height));
		int64_t diff = static_cast<int64_t>(hshd.current_height) - static_cast<int64_t>(m_core.get_current_blockchain_height());
		uint64_t abs_diff = std::abs(diff);
		uint64_t max_block_height = std::max(hshd.current_height, m_core.get_current_blockchain_height());
		uint64_t last_block_v1 = m_core.get_nettype() == TESTNET ? 624633 : m_core.get_nettype() == MAINNET ? 1009826 : (uint64_t)-1;
		uint64_t diff_v2 = max_block_height > last_block_v1 ? std::min(abs_diff, max_block_height - last_block_v1) : 0;
		if(is_inital)
		GULPSF_GLOBAL_PRINT("\n{} Sync data returned a new top block candidate: {} -> {} [Your node is {} blocks ({} days {})]\nSYNCHRONIZATION started", context_str, m_core.get_current_blockchain_height(),
					hshd.current_height, abs_diff, ((abs_diff - diff_v2) / (24 * 60 * 60 / common_config::DIFFICULTY_TARGET)) + (diff_v2 / (24 * 60 * 60 / common_config::DIFFICULTY_TARGET)),
					(0 <= diff ? std::string("behind") : std::string("ahead")));
		else
		GULPSF_GLOBAL_PRINT("\n{} Sync data returned a new top block candidate: {} -> {} [Your node is {} blocks ({} days {})]\nSYNCHRONIZATION started", context_str, m_core.get_current_blockchain_height(),
					hshd.current_height, abs_diff, ((abs_diff - diff_v2) / (24 * 60 * 60 / common_config::DIFFICULTY_TARGET)) + (diff_v2 / (24 * 60 * 60 / common_config::DIFFICULTY_TARGET)),
					(0 <= diff ? std::string("behind") : std::string("ahead")));

		if(hshd.current_height >= m_core.get_current_blockchain_height() + 5) // don't switch to unsafe mode just for a few blocks
			m_core.safesyncmode(false);
		if (m_core.get_target_blockchain_height() == 0) // only when sync starts
		{
			m_sync_timer.resume();
			m_sync_timer.reset();
			m_add_timer.pause();
			m_add_timer.reset();
			m_last_add_end_time = 0;
			m_sync_download_chain_size = 0;
			m_sync_download_objects_size = 0;
		}
	}
	GULPSF_INFO("Remote blockchain height: {}, id: {}", hshd.current_height , hshd.top_id);
	context.m_state = cryptonote_connection_context::state_synchronizing;
	//let the socket to send response to handshake, but request callback, to let send request data after response
	GULPS_LOG_L1( context_str, " requesting callback");
	++context.m_callback_request_count;
	m_p2p->request_callback(context);
    context.m_num_requested = 0;
	return true;
}
//------------------------------------------------------------------------------------------------------------------------
template <class t_core>
bool t_cryptonote_protocol_handler<t_core>::get_payload_sync_data(CORE_SYNC_DATA &hshd)
{
	m_core.get_blockchain_top(hshd.current_height, hshd.top_id);
	hshd.top_version = m_core.get_ideal_hard_fork_version(hshd.current_height);
	hshd.cumulative_difficulty = m_core.get_block_cumulative_difficulty(hshd.current_height);
	hshd.current_height += 1;
	return true;
}
//------------------------------------------------------------------------------------------------------------------------
template <class t_core>
bool t_cryptonote_protocol_handler<t_core>::get_payload_sync_data(blobdata &data)
{
	CORE_SYNC_DATA hsd = boost::value_initialized<CORE_SYNC_DATA>();
	get_payload_sync_data(hsd);
	epee::serialization::store_t_to_binary(hsd, data);
	return true;
}
//------------------------------------------------------------------------------------------------------------------------
template <class t_core>
int t_cryptonote_protocol_handler<t_core>::handle_notify_new_block(int command, NOTIFY_NEW_BLOCK::request &arg, cryptonote_connection_context &context)
{
	GULPS_P2P_MESSAGE("Received NOTIFY_NEW_BLOCK ({} txes)", arg.b.txs.size() );
	if(context.m_state != cryptonote_connection_context::state_normal)
		return 1;
	if(!is_synchronized()) // can happen if a peer connection goes to normal but another thread still hasn't finished adding queued blocks
	{
		GULPS_LOG_L1(context_str," Received new block while syncing, ignored");
		return 1;
	}
	m_core.pause_mine();
	std::vector<block_complete_entry> blocks;
	blocks.push_back(arg.b);
	m_core.prepare_handle_incoming_blocks(blocks);
	for(auto tx_blob_it = arg.b.txs.begin(); tx_blob_it != arg.b.txs.end(); tx_blob_it++)
	{
		cryptonote::tx_verification_context tvc = AUTO_VAL_INIT(tvc);
		m_core.handle_incoming_tx(*tx_blob_it, tvc, true, true, false);
		if(tvc.m_verifivation_failed)
		{
			GULPS_INFO( context_str, " Block verification failed: transaction verification failed, dropping connection");
			drop_connection(context, false, false);
			m_core.cleanup_handle_incoming_blocks();
			m_core.resume_mine();
			return 1;
		}
	}

	block_verification_context bvc = boost::value_initialized<block_verification_context>();
	m_core.handle_incoming_block(arg.b.block, bvc); // got block from handle_notify_new_block
	if(!m_core.cleanup_handle_incoming_blocks(true))
	{
		GULPS_PRINT( context_str, " Failure in cleanup_handle_incoming_blocks");
		m_core.resume_mine();
		return 1;
	}
	m_core.resume_mine();
	if(bvc.m_verifivation_failed)
	{
		GULPS_PRINT( context_str, " Block verification failed, dropping connection");
		drop_connection_with_score(context, bvc.m_bad_pow ? P2P_IP_FAILS_BEFORE_BLOCK : 1, false);
		return 1;
	}
	if(bvc.m_added_to_main_chain)
	{
		//TODO: Add here announce protocol usage
		relay_block(arg, context);
	}
	else if(bvc.m_marked_as_orphaned)
	{
		context.m_needed_objects.clear();
		context.m_state = cryptonote_connection_context::state_synchronizing;
		NOTIFY_REQUEST_CHAIN::request r = boost::value_initialized<NOTIFY_REQUEST_CHAIN::request>();
		context.m_expect_height = m_core.get_current_blockchain_height();
		m_core.get_short_chain_history(r.block_ids);
		handler_request_blocks_history( r.block_ids ); // change the limit(?), sleep(?)
		context.m_last_request_time = boost::posix_time::microsec_clock::universal_time();
		context.m_expect_response = NOTIFY_RESPONSE_CHAIN_ENTRY::ID;
		GULPSF_LOG_L1("{} -->>NOTIFY_REQUEST_CHAIN: m_block_ids.size()={}", context_str, r.block_ids.size());
		post_notify<NOTIFY_REQUEST_CHAIN>(r, context);
		GULPS_LOG_L1("requesting chain");
	}

	// load json & DNS checkpoints every 10min/hour respectively,
	// and verify them with respect to what blocks we already have
	GULPS_CHECK_AND_ASSERT_MES(m_core.update_checkpoints(), 1, "One or more checkpoints loaded from json or dns conflicted with existing checkpoints.");

	return 1;
}
//------------------------------------------------------------------------------------------------------------------------
template <class t_core>
int t_cryptonote_protocol_handler<t_core>::handle_notify_new_fluffy_block(int command, NOTIFY_NEW_FLUFFY_BLOCK::request &arg, cryptonote_connection_context &context)
{
	GULPS_P2P_MESSAGE("Received NOTIFY_NEW_FLUFFY_BLOCK (height {}, {} txes)", arg.current_blockchain_height , arg.b.txs.size() );
	if(context.m_state != cryptonote_connection_context::state_normal)
		return 1;
	if(!is_synchronized()) // can happen if a peer connection goes to normal but another thread still hasn't finished adding queued blocks
	{
		GULPS_LOG_L1( context_str, " Received new block while syncing, ignored");
		return 1;
	}

	m_core.pause_mine();

	block new_block;
	transaction miner_tx;
	if(parse_and_validate_block_from_blob(arg.b.block, new_block))
	{
		// This is a second notification, we must have asked for some missing tx
		if(!context.m_requested_objects.empty())
		{
			// What we asked for != to what we received ..
			if(context.m_requested_objects.size() != arg.b.txs.size())
			{
				GULPSF_LOG_ERROR("{} NOTIFY_NEW_FLUFFY_BLOCK -> request/response mismatch, block = {}, requested = {}, received = {}, dropping connection", context_str, epee::string_tools::pod_to_hex(get_blob_hash(arg.b.block))
					, context.m_requested_objects.size()
					, new_block.tx_hashes.size()
					);

				drop_connection(context, false, false);
				m_core.resume_mine();
				return 1;
			}
		}

		std::vector<blobdata> have_tx;

		// Instead of requesting missing transactions by hash like BTC,
		// we do it by index (thanks to a suggestion from moneromooo) because
		// we're way cooler .. and also because they're smaller than hashes.
		//
		// Also, remember to pepper some whitespace changes around to bother
		// moneromooo ... only because I <3 him.
		std::vector<uint64_t> need_tx_indices;

		transaction tx;
		crypto::hash tx_hash;

		for(auto &tx_blob : arg.b.txs)
		{
			if(parse_and_validate_tx_from_blob(tx_blob, tx))
			{
				try
				{
					if(!get_transaction_hash(tx, tx_hash))
					{
						GULPS_INFO(context_str, " NOTIFY_NEW_FLUFFY_BLOCK: get_transaction_hash failed, dropping connection");

						drop_connection(context, false, false);
						m_core.resume_mine();
						return 1;
					}
				}
				catch(...)
				{
					GULPS_INFO( context_str, " NOTIFY_NEW_FLUFFY_BLOCK: get_transaction_hash failed, exception thrown, dropping connection");

					drop_connection(context, false, false);
					m_core.resume_mine();
					return 1;
				}

				// hijacking m_requested objects in connection context to patch up
				// a possible DOS vector pointed out by @monero-moo where peers keep
				// sending (0...n-1) transactions.
				// If requested objects is not empty, then we must have asked for
				// some missing transacionts, make sure that they're all there.
				//
				// Can I safely re-use this field? I think so, but someone check me!
				if(!context.m_requested_objects.empty())
				{
					auto req_tx_it = context.m_requested_objects.find(tx_hash);
					if(req_tx_it == context.m_requested_objects.end())
					{
						GULPSF_LOG_ERROR("{} Peer sent wrong transaction (NOTIFY_NEW_FLUFFY_BLOCK): transaction with id = {} wasn't requested, dropping connection", context_str, tx_hash );

						drop_connection(context, false, false);
						m_core.resume_mine();
						return 1;
					}

					context.m_requested_objects.erase(req_tx_it);
				}

				// we might already have the tx that the peer
				// sent in our pool, so don't verify again..
				if(!m_core.pool_has_tx(tx_hash))
				{
					GULPSF_LOG_L1("Incoming tx {} not in pool, adding", tx_hash );
					cryptonote::tx_verification_context tvc = AUTO_VAL_INIT(tvc);
					if(!m_core.handle_incoming_tx(tx_blob, tvc, true, true, false) || tvc.m_verifivation_failed)
					{
						GULPS_INFO( context_str, " Block verification failed: transaction verification failed, dropping connection");
						drop_connection(context, false, false);
						m_core.resume_mine();
						return 1;
					}

					//
					// future todo:
					// tx should only not be added to pool if verification failed, but
					// maybe in the future could not be added for other reasons
					// according to monero-moo so keep track of these separately ..
					//
				}
			}
			else
			{
				GULPSF_LOG_ERROR("{} sent wrong tx: failed to parse and validate transaction: {}, dropping connection", context_str, epee::string_tools::buff_to_hex_nodelimer(tx_blob));

				drop_connection(context, false, false);
				m_core.resume_mine();
				return 1;
			}
		}

		// The initial size equality check could have been fooled if the sender
		// gave us the number of transactions we asked for, but not the right
		// ones. This check make sure the transactions we asked for were the
		// ones we received.
		if(context.m_requested_objects.size())
		{
			GULPSF_LOG_ERROR("NOTIFY_NEW_FLUFFY_BLOCK: peer sent the number of transaction requested, but not the actual transactions requested, context.m_requested_objects.size() = {}, dropping connection"
				, context.m_requested_objects.size());

			drop_connection(context, false, false);
			m_core.resume_mine();
			return 1;
		}

		size_t tx_idx = 0;
		for(auto &tx_hash : new_block.tx_hashes)
		{
			cryptonote::blobdata txblob;
			if(m_core.get_pool_transaction(tx_hash, txblob))
			{
				have_tx.push_back(txblob);
			}
			else
			{
				std::vector<crypto::hash> tx_ids;
				std::vector<transaction> txes;
				std::vector<crypto::hash> missing;
				tx_ids.push_back(tx_hash);
				if(m_core.get_transactions(tx_ids, txes, missing) && missing.empty())
				{
					if(txes.size() == 1)
					{
						have_tx.push_back(tx_to_blob(txes.front()));
					}
					else
					{
						GULPSF_LOG_L1("1 tx requested, none not found, but {} returned", txes.size() );
						m_core.resume_mine();
						return 1;
					}
				}
				else
				{
					GULPSF_LOG_L1("Tx {} not found in pool", tx_hash );
					need_tx_indices.push_back(tx_idx);
				}
			}

			++tx_idx;
		}

		if(!need_tx_indices.empty()) // drats, we don't have everything..
		{
			// request non-mempool txs
			GULPSF_LOG_L1("We are missing {} txes for this fluffy block", need_tx_indices.size() );
			for(auto txidx : need_tx_indices)
				GULPSF_LOG_L1("  tx {}", new_block.tx_hashes[txidx]);
			NOTIFY_REQUEST_FLUFFY_MISSING_TX::request missing_tx_req;
			missing_tx_req.block_hash = get_block_hash(new_block);
			missing_tx_req.current_blockchain_height = arg.current_blockchain_height;
			missing_tx_req.missing_tx_indices = std::move(need_tx_indices);

			m_core.resume_mine();
			post_notify<NOTIFY_REQUEST_FLUFFY_MISSING_TX>(missing_tx_req, context);
		}
		else // whoo-hoo we've got em all ..
		{
			GULPS_LOG_L1("We have all needed txes for this fluffy block");

			block_complete_entry b;
			b.block = arg.b.block;
			b.txs = have_tx;

			std::vector<block_complete_entry> blocks;
			blocks.push_back(b);
			m_core.prepare_handle_incoming_blocks(blocks);

			block_verification_context bvc = boost::value_initialized<block_verification_context>();
			m_core.handle_incoming_block(arg.b.block, bvc); // got block from handle_notify_new_block
			if(!m_core.cleanup_handle_incoming_blocks(true))
			{
				GULPS_PRINT( context_str, " Failure in cleanup_handle_incoming_blocks");
				m_core.resume_mine();
				return 1;
			}
			m_core.resume_mine();

			if(bvc.m_verifivation_failed)
			{
				GULPS_PRINT( context_str, " Block verification failed, dropping connection");
				drop_connection_with_score(context, bvc.m_bad_pow ? P2P_IP_FAILS_BEFORE_BLOCK : 1, false);
				return 1;
			}
			if(bvc.m_added_to_main_chain)
			{
				//TODO: Add here announce protocol usage
				NOTIFY_NEW_BLOCK::request reg_arg = AUTO_VAL_INIT(reg_arg);
				reg_arg.current_blockchain_height = arg.current_blockchain_height;
				reg_arg.b = b;
				relay_block(reg_arg, context);
			}
			else if(bvc.m_marked_as_orphaned)
			{
				context.m_needed_objects.clear();
				context.m_state = cryptonote_connection_context::state_synchronizing;
				NOTIFY_REQUEST_CHAIN::request r = boost::value_initialized<NOTIFY_REQUEST_CHAIN::request>();
				context.m_expect_height = m_core.get_current_blockchain_height();
				m_core.get_short_chain_history(r.block_ids);
				handler_request_blocks_history( r.block_ids ); // change the limit(?), sleep(?)
				context.m_last_request_time = boost::posix_time::microsec_clock::universal_time();
				context.m_expect_response = NOTIFY_RESPONSE_CHAIN_ENTRY::ID;
				GULPSF_LOG_L1("{} -->>NOTIFY_REQUEST_CHAIN: m_block_ids.size()={}", context_str, r.block_ids.size());
				post_notify<NOTIFY_REQUEST_CHAIN>(r, context);
				GULPS_LOG_L1("requesting chain");
			}
			// load json & DNS checkpoints every 10min/hour respectively,
			// and verify them with respect to what blocks we already have
			GULPS_CHECK_AND_ASSERT_MES(m_core.update_checkpoints(), 1, "One or more checkpoints loaded from json or dns conflicted with existing checkpoints.");
		}
	}
	else
	{
		GULPSF_LOG_ERROR("sent wrong block: failed to parse and validate block: {}, dropping connection", epee::string_tools::buff_to_hex_nodelimer(arg.b.block)
			);

		m_core.resume_mine();
		drop_connection(context, false, false);

		return 1;
	}

	return 1;
}
//------------------------------------------------------------------------------------------------------------------------
template <class t_core>
int t_cryptonote_protocol_handler<t_core>::handle_request_fluffy_missing_tx(int command, NOTIFY_REQUEST_FLUFFY_MISSING_TX::request &arg, cryptonote_connection_context &context)
{
	GULPS_P2P_MESSAGE("Received NOTIFY_REQUEST_FLUFFY_MISSING_TX ({} txes), block hash {}", arg.missing_tx_indices.size() , arg.block_hash);

	std::vector<std::pair<cryptonote::blobdata, block>> local_blocks;
	std::vector<cryptonote::blobdata> local_txs;

	block b;
	if(!m_core.get_block_by_hash(arg.block_hash, b))
	{
		GULPSF_LOG_ERROR("{} failed to find block: {}, dropping connection", context_str, arg.block_hash );
		drop_connection(context, false, false);
		return 1;
	}

	std::vector<crypto::hash> txids;
	NOTIFY_NEW_FLUFFY_BLOCK::request fluffy_response;
	fluffy_response.b.block = t_serializable_object_to_blob(b);
	fluffy_response.current_blockchain_height = arg.current_blockchain_height;
	for(auto &tx_idx : arg.missing_tx_indices)
	{
		if(tx_idx < b.tx_hashes.size())
		{
			GULPSF_LOG_L1("  tx {}", b.tx_hashes[tx_idx]);
			txids.push_back(b.tx_hashes[tx_idx]);
		}
		else
		{
			GULPSF_LOG_ERROR("{} Failed to handle request NOTIFY_REQUEST_FLUFFY_MISSING_TX, request is asking for a tx whose index is out of bounds , tx index = {}, block tx count {}, block_height = {}, dropping connection",  context_str, tx_idx , b.tx_hashes.size()
				, arg.current_blockchain_height);


			drop_connection(context, false, false);
			return 1;
		}
	}

	std::vector<cryptonote::transaction> txs;
	std::vector<crypto::hash> missed;
	if(!m_core.get_transactions(txids, txs, missed))
	{
		GULPS_LOG_ERROR( context_str, " Failed to handle request NOTIFY_REQUEST_FLUFFY_MISSING_TX, failed to get requested transactions");
		drop_connection(context, false, false);
		return 1;
	}
	if(!missed.empty() || txs.size() != txids.size())
	{
		GULPSF_LOG_ERROR("{} Failed to handle request NOTIFY_REQUEST_FLUFFY_MISSING_TX, {} requested transactions not found, dropping connection", context_str, missed.size() );
		drop_connection(context, false, false);
		return 1;
	}

	for(auto &tx : txs)
	{
		fluffy_response.b.txs.push_back(t_serializable_object_to_blob(tx));
	}

	GULPSF_LOG_L1("{} -->>NOTIFY_RESPONSE_FLUFFY_MISSING_TX: , txs.size()={}, rsp.current_blockchain_height={}", context_str, fluffy_response.b.txs.size() , fluffy_response.current_blockchain_height);

	post_notify<NOTIFY_NEW_FLUFFY_BLOCK>(fluffy_response, context);
	return 1;
}
//------------------------------------------------------------------------------------------------------------------------
template <class t_core>
int t_cryptonote_protocol_handler<t_core>::handle_notify_new_transactions(int command, NOTIFY_NEW_TRANSACTIONS::request &arg, cryptonote_connection_context &context)
{
	GULPS_P2P_MESSAGE("Received NOTIFY_NEW_TRANSACTIONS ({} txes)", arg.txs.size() );
	if(context.m_state != cryptonote_connection_context::state_normal)
		return 1;

	// while syncing, core will lock for a long time, so we ignore
	// those txes as they aren't really needed anyway, and avoid a
	// long block before replying
	if(!is_synchronized())
	{
		GULPS_LOG_L1( context_str, " Received new tx while syncing, ignored");
		return 1;
	}

    std::vector<cryptonote::blobdata> newtxs;
    newtxs.reserve(arg.txs.size());
    for (size_t i = 0; i < arg.txs.size(); ++i)
	{
		cryptonote::tx_verification_context tvc = AUTO_VAL_INIT(tvc);
		m_core.handle_incoming_tx(arg.txs[i], tvc, false, true, false);
		if(tvc.m_verifivation_failed)
		{
			GULPS_INFO( context_str, " Tx verification failed, dropping connection");
			drop_connection(context, false, false);
			return 1;
		}
		if(tvc.m_should_be_relayed)
			newtxs.push_back(std::move(arg.txs[i]));
	}
    arg.txs = std::move(newtxs);

	if(arg.txs.size())
	{
		//TODO: add announce usage here
		relay_transactions(arg, context);
	}

	return 1;
}
//------------------------------------------------------------------------------------------------------------------------
template <class t_core>
int t_cryptonote_protocol_handler<t_core>::handle_request_get_objects(int command, NOTIFY_REQUEST_GET_OBJECTS::request &arg, cryptonote_connection_context &context)
{
	GULPS_P2P_MESSAGE("Received NOTIFY_REQUEST_GET_OBJECTS ({} blocks, {} txes)", arg.blocks.size() , arg.txs.size() );
	NOTIFY_RESPONSE_GET_OBJECTS::request rsp;
	if(!m_core.handle_get_objects(arg, rsp, context))
	{
		GULPS_ERROR( context_str," failed to handle request NOTIFY_REQUEST_GET_OBJECTS, dropping connection");
		drop_connection(context, false, false);
		return 1;
	}
    context.m_last_request_time = boost::posix_time::microsec_clock::universal_time();
	GULPSF_LOG_L1("{} -->>NOTIFY_RESPONSE_GET_OBJECTS: blocks.size()={}, txs.size()={}, rsp.m_current_blockchain_height={}, missed_ids.size()={}", context_str, rsp.blocks.size() , rsp.txs.size() , rsp.current_blockchain_height , rsp.missed_ids.size());
	post_notify<NOTIFY_RESPONSE_GET_OBJECTS>(rsp, context);
	//handler_response_blocks_now(sizeof(rsp)); // XXX
	//handler_response_blocks_now(200);
	return 1;
}
//------------------------------------------------------------------------------------------------------------------------

template <class t_core>
double t_cryptonote_protocol_handler<t_core>::get_avg_block_size()
{
	CRITICAL_REGION_LOCAL(m_buffer_mutex);
	if(m_avg_buffer.empty())
	{
		GULPS_WARN("m_avg_buffer.size() == 0");
		return 500;
	}
	double avg = 0;
	for(const auto &element : m_avg_buffer)
		avg += element;
	return avg / m_avg_buffer.size();
}

template <class t_core>
int t_cryptonote_protocol_handler<t_core>::handle_response_get_objects(int command, NOTIFY_RESPONSE_GET_OBJECTS::request &arg, cryptonote_connection_context &context)
{
	GULPS_P2P_MESSAGE("Received NOTIFY_RESPONSE_GET_OBJECTS ({} blocks, {} txes)", arg.blocks.size() , arg.txs.size() );

	boost::posix_time::ptime request_time = context.m_last_request_time;
	context.m_last_request_time = boost::date_time::not_a_date_time;

	if (context.m_expect_response != NOTIFY_RESPONSE_GET_OBJECTS::ID)
	{
		GULPS_LOG_ERROR("Got NOTIFY_RESPONSE_GET_OBJECTS out of the blue, dropping connection");
		drop_connection(context, true, false);
		return 1;
	}
	context.m_expect_response = 0;

	// calculate size of request
	size_t size = 0;
	for(const auto &element : arg.txs)
		size += element.size();

	size_t blocks_size = 0;
	for(const auto &element : arg.blocks)
	{
		blocks_size += element.block.size();
		for(const auto &tx : element.txs)
			blocks_size += tx.size();
	}
	size += blocks_size;

	for(const auto &element : arg.missed_ids)
		size += sizeof(element.data);

	size += sizeof(arg.current_blockchain_height);
	{
		CRITICAL_REGION_LOCAL(m_buffer_mutex);
		m_avg_buffer.push_back(size);
	}
    m_sync_download_objects_size += size;
	GULPSF_LOG_L1("{} downloaded {} bytes worth of blocks", context_str, size);

	/*using namespace boost::chrono;
      auto point = steady_clock::now();
      auto time_from_epoh = point.time_since_epoch();
      auto sec = duration_cast< seconds >( time_from_epoh ).count();*/

	//epee::net_utils::network_throttle_manager::get_global_throttle_inreq().logger_handle_net("log/dr-monero/net/req-all.data", sec, get_avg_block_size());

	if(context.m_last_response_height > arg.current_blockchain_height)
	{
		GULPSF_LOG_ERROR("{} sent wrong NOTIFY_HAVE_OBJECTS: arg.m_current_blockchain_height={} < m_last_response_height={}, dropping connection", context_str, arg.current_blockchain_height
																							  , context.m_last_response_height );
		drop_connection(context, false, false);
		return 1;
	}

	if (arg.current_blockchain_height < context.m_remote_blockchain_height)
	{
		GULPSF_LOG_L1("{} Claims {}, claimed {} before", context_str, arg.current_blockchain_height, context.m_remote_blockchain_height);
		hit_score(context, 1);
	}

	context.m_remote_blockchain_height = arg.current_blockchain_height;
	if(context.m_remote_blockchain_height > m_core.get_target_blockchain_height())
		m_core.set_target_blockchain_height(context.m_remote_blockchain_height);

	std::vector<crypto::hash> block_hashes;
	block_hashes.reserve(arg.blocks.size());
	const boost::posix_time::ptime now = boost::posix_time::microsec_clock::universal_time();
	uint64_t start_height = std::numeric_limits<uint64_t>::max();
	cryptonote::block b;
	for(const block_complete_entry &block_entry : arg.blocks)
	{
		if(m_stopping)
		{
			return 1;
		}

		if(!parse_and_validate_block_from_blob(block_entry.block, b))
		{
			GULPSF_LOG_ERROR("{} sent wrong block: failed to parse and validate block: {}, dropping connection", context_str, epee::string_tools::buff_to_hex_nodelimer(block_entry.block) );
			drop_connection(context, false, false);
			return 1;
		}
		if(b.miner_tx.vin.size() != 1 || b.miner_tx.vin.front().type() != typeid(txin_gen))
		{
			GULPSF_LOG_ERROR("{} sent wrong block: block: miner tx does not have exactly one txin_gen input{}, dropping connection", context_str, epee::string_tools::buff_to_hex_nodelimer(block_entry.block) );
			drop_connection(context, false, false);
			return 1;
		}
		if(start_height == std::numeric_limits<uint64_t>::max())
			start_height = boost::get<txin_gen>(b.miner_tx.vin[0]).height;

		const crypto::hash block_hash = get_block_hash(b);
		auto req_it = context.m_requested_objects.find(block_hash);
		if(req_it == context.m_requested_objects.end())
		{
			GULPSF_LOG_ERROR("{} sent wrong NOTIFY_RESPONSE_GET_OBJECTS: block with id={} wasn't requested, dropping connection", context_str, epee::string_tools::pod_to_hex(get_blob_hash(block_entry.block))
																						);
			drop_connection(context, false, false);
			return 1;
		}
		if(b.tx_hashes.size() != block_entry.txs.size())
		{
			GULPSF_LOG_ERROR("{} sent wrong NOTIFY_RESPONSE_GET_OBJECTS: block with id={}, tx_hashes.size()={} mismatch with block_complete_entry.m_txs.size()={}, dropping connection"
													, context_str, epee::string_tools::pod_to_hex(get_blob_hash(block_entry.block))
													, b.tx_hashes.size() , block_entry.txs.size());
			drop_connection(context, false, false);
			return 1;
		}

		context.m_requested_objects.erase(req_it);
		block_hashes.push_back(block_hash);
	}

	if(context.m_requested_objects.size())
	{
		GULPSF_LOG_L1("returned not all requested objects (context.m_requested_objects.size()={}), dropping connection", context.m_requested_objects.size() );
		drop_connection(context, false, false);
		return 1;
	}

	// get the last parsed block, which should be the highest one
	const crypto::hash last_block_hash = cryptonote::get_block_hash(b);
	if(m_core.have_block(last_block_hash))
	{
		const uint64_t subchain_height = start_height + arg.blocks.size();
		GULPSF_LOG_L1("{} These are old blocks, ignoring: blocks {} - {}, blockchain height {}", context_str, start_height , (subchain_height - 1) , m_core.get_current_blockchain_height());
		m_block_queue.remove_spans(context.m_connection_id, start_height);
		goto skip;
	}

	{
		GULPS_OUTPUTF(gulps::OUT_LOG_0, gulps::LEVEL_DEBUG, gulps_major_cat::c_str(), gulps_minor_cat::c_str(), gulps::COLOR_BOLD_YELLOW, "{} Got NEW BLOCKS inside of {}: size: {}, blocks: {} - {}",
			context_str, __FUNCTION__, arg.blocks.size(), start_height, (start_height + arg.blocks.size() - 1));

		// add that new span to the block queue
		const boost::posix_time::time_duration dt = now - context.m_last_request_time;
		const float rate = size * 1e6 / (dt.total_microseconds() + 1);
		GULPSF_LOG_L1("{} adding span: {} at height {}, {} seconds, {} kB/s, size now {} MB", context_str, arg.blocks.size() , start_height , dt.total_microseconds() / 1e6 , (rate / 1e3) , (m_block_queue.get_data_size() + blocks_size) / 1048576.f );
		m_block_queue.add_blocks(start_height, arg.blocks, context.m_connection_id, context.m_remote_address, rate, blocks_size);

		context.m_last_known_hash = last_block_hash;

		if(!m_core.get_test_drop_download() || !m_core.get_test_drop_download_height())
		{ // DISCARD BLOCKS for testing
			return 1;
		}
	}

skip:
	try_add_next_blocks(context);
	return 1;
}

// Get an estimate for the remaining sync time from given current to target blockchain height, in seconds
template<class t_core>
uint64_t t_cryptonote_protocol_handler<t_core>::get_estimated_remaining_sync_seconds(uint64_t current_blockchain_height, uint64_t target_blockchain_height)
{
	// The average sync speed varies so much, even averaged over quite long time periods like 10 minutes,
	// that using some sliding window would be difficult to implement without often leading to bad estimates.
	// The simplest strategy - always average sync speed over the maximum available interval i.e. since sync
	// started at all (from "m_sync_start_time" and "m_sync_start_height") - gives already useful results
	// and seems to be quite robust. Some quite special cases like "Internet connection suddenly becoming
	// much faster after syncing already a long time, and staying fast" are not well supported however.

	if (target_blockchain_height <= current_blockchain_height)
	{
		// Syncing stuck, or other special circumstance: Avoid errors, simply give back 0
		return 0;
	}

	const boost::posix_time::ptime now = boost::posix_time::microsec_clock::universal_time();
	const boost::posix_time::time_duration sync_time = now - m_sync_start_time;
	cryptonote::network_type nettype = m_core.get_nettype();

	// Don't simply use remaining number of blocks for the estimate but "sync weight" as provided by
	// "cumulative_block_sync_weight" which knows about strongly varying Monero mainnet block sizes
	uint64_t synced_weight = tools::cumulative_block_sync_weight(nettype, m_sync_start_height, current_blockchain_height - m_sync_start_height);
	float us_per_weight = (float)sync_time.total_microseconds() / (float)synced_weight;
	uint64_t remaining_weight = tools::cumulative_block_sync_weight(nettype, current_blockchain_height, target_blockchain_height - current_blockchain_height);
	float remaining_us = us_per_weight * (float)remaining_weight;
	return (uint64_t)(remaining_us / 1e6);
}

// Return a textual remaining sync time estimate, or the empty string if waiting period not yet over
template<class t_core>
std::string t_cryptonote_protocol_handler<t_core>::get_periodic_sync_estimate(uint64_t current_blockchain_height, uint64_t target_blockchain_height)
{
	std::string text = "";
	const boost::posix_time::ptime now = boost::posix_time::microsec_clock::universal_time();
	boost::posix_time::time_duration period_sync_time = now - m_period_start_time;
	if (period_sync_time > boost::posix_time::minutes(2))
	{
		// Period is over, time to report another estimate
		uint64_t remaining_seconds = get_estimated_remaining_sync_seconds(current_blockchain_height, target_blockchain_height);
		text = tools::get_human_readable_timespan(remaining_seconds);

		// Start the new period
		m_period_start_time = now;
	}
	return text;
}

template <class t_core>
int t_cryptonote_protocol_handler<t_core>::try_add_next_blocks(cryptonote_connection_context &context)
{
	bool force_next_span = false;

	{
		// We try to lock the sync lock. If we can, it means no other thread is
		// currently adding blocks, so we do that for as long as we can from the
		// block queue. Then, we go back to download.
		const boost::unique_lock<boost::mutex> sync{m_sync_lock, boost::try_to_lock};
		if(!sync.owns_lock())
		{
			GULPS_INFO("Failed to lock m_sync_lock, going back to download");
			goto skip;
		}
		GULPS_LOG_L1( context_str," lock m_sync_lock, adding blocks to chain...");

		{
			m_core.pause_mine();
			m_add_timer.resume();
			epee::misc_utils::auto_scope_leave_caller scope_exit_handler = epee::misc_utils::create_scope_leave_handler([this, &starting]() {
				m_add_timer.pause();
				m_core.resume_mine();
				if (!starting)
					m_last_add_end_time = tools::get_tick_count();
			});
			m_sync_start_time = boost::posix_time::microsec_clock::universal_time();
			m_sync_start_height = m_core.get_current_blockchain_height();
			m_period_start_time = m_sync_start_time;

			while(1)
			{
				const uint64_t previous_height = m_core.get_current_blockchain_height();
				uint64_t start_height;
				std::vector<cryptonote::block_complete_entry> blocks;
				boost::uuids::uuid span_connection_id;
                epee::net_utils::network_address span_origin;
          		if (!m_block_queue.get_next_span(start_height, blocks, span_connection_id, span_origin))
				{
					GULPS_LOG_L1( context_str," no next span found, going back to download");
					break;
				}
				GULPSF_LOG_L1("{} next span in the queue has blocks {}-{}, we need {}", context_str, start_height , (start_height + blocks.size() - 1) , previous_height);

				if(blocks.empty())
				{
					GULPS_ERROR("Next span has no blocks");
					m_block_queue.remove_spans(span_connection_id, start_height);
					break;
				}

				block new_block;
				if(!parse_and_validate_block_from_blob(blocks.front().block, new_block))
				{
					GULPS_ERROR("Failed to parse block, but it should already have been parsed");
					m_block_queue.remove_spans(span_connection_id, start_height);
					break;
				}
				bool parent_known = m_core.have_block(new_block.prev_id);
				if(!parent_known)
				{
					// it could be:
					//  - later in the current chain
					//  - later in an alt chain
					//  - orphan
					// if it was requested, then it'll be resolved later, otherwise it's an orphan
					bool parent_requested = m_block_queue.requested(new_block.prev_id);
					if(!parent_requested)
					{
						// this can happen if a connection was sicced onto a late span, if it did not have those blocks,
						// since we don't know that at the sic time
						GULPS_ERROR( context_str, " Got block with unknown parent which was not requested - querying block hashes");
						m_block_queue.remove_spans(span_connection_id, start_height);
						context.m_needed_objects.clear();
						context.m_last_response_height = 0;
						goto skip;
					}

					// parent was requested, so we wait for it to be retrieved
					GULPS_INFO(" parent was requested, we'll get back to it");
					break;
				}

				const boost::posix_time::ptime start = boost::posix_time::microsec_clock::universal_time();

				if (starting)
				{
					starting = false;
					if (m_last_add_end_time)
					{
						const uint64_t tnow = tools::get_tick_count();
						const uint64_t ns = tools::ticks_to_ns(tnow - m_last_add_end_time);
						GULPSF_INFO("Restarting adding block after idle for {} seconds", ns/1e9);
					}
				}

				m_core.prepare_handle_incoming_blocks(blocks);

				uint64_t block_process_time_full = 0, transactions_process_time_full = 0;
				size_t num_txs = 0;
				for(const block_complete_entry &block_entry : blocks)
				{
					if(m_stopping)
					{
						m_core.cleanup_handle_incoming_blocks();
						return 1;
					}

					// process transactions
					TIME_MEASURE_START(transactions_process_time);
					num_txs += block_entry.txs.size();
					std::vector<tx_verification_context> tvc;
					m_core.handle_incoming_txs(block_entry.txs, tvc, true, true, false);
					if(tvc.size() != block_entry.txs.size())
					{
						GULPS_ERROR( context_str, " Internal error: tvc.size() != block_entry.txs.size()");
						return 1;
					}
					std::vector<blobdata>::const_iterator it = block_entry.txs.begin();
					for(size_t i = 0; i < tvc.size(); ++i, ++it)
					{
						if(tvc[i].m_verifivation_failed)
						{
							if(!m_p2p->for_connection(span_connection_id, [&](cryptonote_connection_context &context, nodetool::peerid_type peer_id, uint32_t f) -> bool {
								   GULPSF_LOG_ERROR("{} transaction verification failed on NOTIFY_RESPONSE_GET_OBJECTS, tx_id = {}, dropping connection", context_str, epee::string_tools::pod_to_hex(get_blob_hash(*it)) );
								   drop_connection(context, false, true);
								   return 1;
							   }))
								GULPS_ERROR( context_str, " span connection id not found");

							if(!m_core.cleanup_handle_incoming_blocks())
							{
								GULPS_ERROR( context_str," Failure in cleanup_handle_incoming_blocks");
								return 1;
							}
							// in case the peer had dropped beforehand, remove the span anyway so other threads can wake up and get it
							m_block_queue.remove_spans(span_connection_id, start_height);
							return 1;
						}
					}
					TIME_MEASURE_FINISH(transactions_process_time);
					transactions_process_time_full += transactions_process_time;

					// process block

					TIME_MEASURE_START(block_process_time);
					block_verification_context bvc = boost::value_initialized<block_verification_context>();

					m_core.handle_incoming_block(block_entry.block, bvc, false); // <--- process block

					if(bvc.m_verifivation_failed)
					{
						if(!m_p2p->for_connection(span_connection_id, [&](cryptonote_connection_context &context, nodetool::peerid_type peer_id, uint32_t f) -> bool {
							   GULPS_INFO( context_str, " Block verification failed, dropping connection");
								drop_connection_with_score(context, bvc.m_bad_pow ? P2P_IP_FAILS_BEFORE_BLOCK : 1, true);
							   return 1;
						   }))
							GULPS_ERROR( context_str, " span connection id not found");

						if(!m_core.cleanup_handle_incoming_blocks())
						{
							GULPS_ERROR( context_str, " Failure in cleanup_handle_incoming_blocks");
							return 1;
						}

						// in case the peer had dropped beforehand, remove the span anyway so other threads can wake up and get it
						m_block_queue.remove_spans(span_connection_id, start_height);
						return 1;
					}
					if(bvc.m_marked_as_orphaned)
					{
						if(!m_p2p->for_connection(span_connection_id, [&](cryptonote_connection_context &context, nodetool::peerid_type peer_id, uint32_t f) -> bool {
								GULPS_INFO( context_str, " Block received at sync phase was marked as orphaned, dropping connection");
								drop_connection(context, true, true);
								return 1;
						}))
						GULPS_ERROR( context_str, " span connection id not found");

						if(!m_core.cleanup_handle_incoming_blocks())
						{
							GULPS_ERROR( context_str, " Failure in cleanup_handle_incoming_blocks");
							return 1;
						}

						// in case the peer had dropped beforehand, remove the span anyway so other threads can wake up and get it
						m_block_queue.remove_spans(span_connection_id, start_height);
						return 1;
					}

					TIME_MEASURE_FINISH(block_process_time);
					block_process_time_full += block_process_time;

				} // each download block

				GULPSF_CAT_INFO("sync-info", "Block process time ({} blocks P{} txs):{} ({}/{}) ms", blocks.size(), num_txs, block_process_time_full + transactions_process_time_full, transactions_process_time_full, block_process_time_full);

				if(!m_core.cleanup_handle_incoming_blocks())
				{
					GULPS_ERROR( context_str, " Failure in cleanup_handle_incoming_blocks");
					return 1;
				}

				m_block_queue.remove_spans(span_connection_id, start_height);
				const uint64_t current_blockchain_height = m_core.get_current_blockchain_height();
				if (current_blockchain_height > previous_height)
				{
					const uint64_t target_blockchain_height = m_core.get_target_blockchain_height();
					const boost::posix_time::time_duration dt = boost::posix_time::microsec_clock::universal_time() - start;
					std::string progress_message = "";
					if (current_blockchain_height < target_blockchain_height)
					{
						uint64_t completion_percent = (current_blockchain_height * 100 / target_blockchain_height);
						if (completion_percent == 100) // never show 100% if not actually up to date
							completion_percent = 99;
						progress_message = " (" + std::to_string(completion_percent) + "%, "
							+ std::to_string(target_blockchain_height - current_blockchain_height) + " left";
						std::string time_message = get_periodic_sync_estimate(current_blockchain_height, target_blockchain_height);
						if (!time_message.empty())
						{
							uint64_t total_blocks_to_sync = target_blockchain_height - m_sync_start_height;
							uint64_t total_blocks_synced = current_blockchain_height - m_sync_start_height;
							progress_message += ", " + std::to_string(total_blocks_synced * 100 / total_blocks_to_sync) + "% of total synced";
							progress_message += ", estimated " + time_message + " left";
						}
						progress_message += ")";
					}
					std::string timing_message = "";
					timing_message = std::string(" (") + std::to_string(dt.total_microseconds()/1e6) + " sec, "
						+ std::to_string((current_blockchain_height - previous_height) * 1e6 / dt.total_microseconds())
						+ " blocks/sec), " + std::to_string(m_block_queue.get_data_size() / 1048576.f) + " MB queued";
					GULPSF_GLOBAL_PRINT_CLR(gulps::COLOR_BOLD_YELLOW, "{} Synced {}/{} {} {}", 
						current_blockchain_height, target_blockchain_height, progress_message, timing_message);
					GULPS_CAT_LOG_L1("global","", m_block_queue.get_overview());
				}
			}
		}

		if(should_download_next_span(context, false))
		{
			context.m_needed_objects.clear();
			context.m_last_response_height = 0;
			force_next_span = true;
		}
	}

skip:
	if(!request_missing_objects(context, true, force_next_span))
	{
		GULPS_ERROR( context_str, " Failed to request missing objects, dropping connection");
		drop_connection(context, false, false);
		return 1;
	}
	return 1;
}
//------------------------------------------------------------------------------------------------------------------------
template <class t_core>
bool t_cryptonote_protocol_handler<t_core>::on_idle()
{
	m_idle_peer_kicker.do_call(boost::bind(&t_cryptonote_protocol_handler<t_core>::kick_idle_peers, this));
	return m_core.on_idle();
}
//------------------------------------------------------------------------------------------------------------------------
template<class t_core>
bool t_cryptonote_protocol_handler<t_core>::kick_idle_peers()
{
	GULPS_LOG_L2("Checking for idle peers...");
	m_p2p->for_each_connection([&](cryptonote_connection_context& context, nodetool::peerid_type peer_id, uint32_t support_flags)->bool
	{
		if (context.m_state == cryptonote_connection_context::state_synchronizing && context.m_last_request_time != boost::date_time::not_a_date_time)
		{
			const boost::posix_time::ptime now = boost::posix_time::microsec_clock::universal_time();
			const boost::posix_time::time_duration dt = now - context.m_last_request_time;
			const auto ms = dt.total_microseconds();
			if (ms > IDLE_PEER_KICK_TIME || (context.m_expect_response && ms > NON_RESPONSIVE_PEER_KICK_TIME))
			{
				context.m_idle_peer_notification = true;
				GULPS_INFO("requesting callback");
				++context.m_callback_request_count;
				m_p2p->request_callback(context);
				GULPS_INFO("requesting callback");
			}
		}
		return true;
	});

	return true;
}
//------------------------------------------------------------------------------------------------------------------------
template <class t_core>
int t_cryptonote_protocol_handler<t_core>::handle_request_chain(int command, NOTIFY_REQUEST_CHAIN::request &arg, cryptonote_connection_context &context)
{
	GULPS_P2P_MESSAGE("Received NOTIFY_REQUEST_CHAIN ({} blocks", arg.block_ids.size() );
	NOTIFY_RESPONSE_CHAIN_ENTRY::request r;
	if(!m_core.find_blockchain_supplement(arg.block_ids, r))
	{
		GULPS_ERROR( context_str, " Failed to handle NOTIFY_REQUEST_CHAIN.");
		drop_connection(context, false, false);
		return 1;
	}
	GULPSF_LOG_L1("{}-->>NOTIFY_RESPONSE_CHAIN_ENTRY: m_start_height={}, m_total_height={}, m_block_ids.size()={}", context_str, r.start_height , r.total_height , r.m_block_ids.size());
	post_notify<NOTIFY_RESPONSE_CHAIN_ENTRY>(r, context);
	return 1;
}
//------------------------------------------------------------------------------------------------------------------------
template <class t_core>
bool t_cryptonote_protocol_handler<t_core>::should_download_next_span(cryptonote_connection_context &context, bool standby) const
{
	boost::uuids::uuid span_connection_id;
	boost::posix_time::ptime request_time;
	std::pair<uint64_t, uint64_t> span;
	boost::uuids::uuid connection_id;
	bool filled;

	const uint64_t blockchain_height = m_core.get_current_blockchain_height();
	if(context.m_remote_blockchain_height <= blockchain_height)
		return false;

	const boost::posix_time::ptime now = boost::posix_time::microsec_clock::universal_time();
	if(!m_block_queue.has_next_span(blockchain_height, filled, request_time, connection_id))
	{
		GULPS_LOG_L1(context_str, " we should download it as no peer reserved it");
		return true;
	}
	if(!filled)
	{
		const long dt = (now - request_time).total_microseconds();
		if(dt >= REQUEST_NEXT_SCHEDULED_SPAN_THRESHOLD)
		{
			GULPS_LOG_L1(context_str, " we should download it as it's not been received yet after ", dt/1e6);
			return true;
		}

		// in standby, be ready to double download early since we're idling anyway
		// let the fastest peer trigger first
		const double dl_speed = context.m_current_speed_down;
		if(standby && dt >= REQUEST_NEXT_SCHEDULED_SPAN_THRESHOLD_STANDBY && dl_speed > 0)
		{
			bool download = false;
			if (m_p2p->for_connection(connection_id, [&](cryptonote_connection_context& ctx, nodetool::peerid_type peer_id, uint32_t f)->bool{
				const time_t nowt = time(NULL);
				const time_t time_since_last_recv = nowt - ctx.m_last_recv;
				const float last_activity = std::min((float)time_since_last_recv, dt/1e6f);
				const bool stalled = last_activity > LAST_ACTIVITY_STALL_THRESHOLD;
				if(stalled)
				{
					GULPS_LOG_L1(context_str, " we should download it as the downloading peer is stalling for ",
						nowt - ctx.m_last_recv, " seconds");
					download = true;
					return true;
				}

				// estimate the standby peer can give us 80% of its max speed
				// and let it download if that speed is > N times as fast as the current one
				// N starts at 10 after REQUEST_NEXT_SCHEDULED_SPAN_THRESHOLD_STANDBY,
				// decreases to 1.25 at REQUEST_NEXT_SCHEDULED_SPAN_THRESHOLD,
				// so that at times goes without the download being done, a retry becomes easier
				const float max_multiplier = 10.f;
				const float min_multiplier = 1.25f;
				float multiplier = max_multiplier;
				if(dt >= REQUEST_NEXT_SCHEDULED_SPAN_THRESHOLD_STANDBY)
				{
					multiplier = max_multiplier - (dt-REQUEST_NEXT_SCHEDULED_SPAN_THRESHOLD_STANDBY) * (max_multiplier - min_multiplier) / (REQUEST_NEXT_SCHEDULED_SPAN_THRESHOLD - REQUEST_NEXT_SCHEDULED_SPAN_THRESHOLD_STANDBY);
					multiplier = std::min(max_multiplier, std::max(min_multiplier, multiplier));
				}
				if(dl_speed * .8f > ctx.m_current_speed_down * multiplier)
				{
					GULPS_LOG_L1(context_str, " we should download it as we are substantially faster (",
						dl_speed, " vs ", ctx.m_current_speed_down, ", multiplier ", multiplier, " after ", 
						dt/1e6, " seconds)");

					download = true;
					return true;
				}
				return true;
			}))
			{
			if(download)
				return true;
			}
			else
			{
				GULPS_LOG_L1(context_str, " we should download it as the downloading peer is unexpectedly not known to us");
				return true;
			}
		}
	}
	return false;
}
//------------------------------------------------------------------------------------------------------------------------
template<class t_core>
size_t t_cryptonote_protocol_handler<t_core>::skip_unneeded_hashes(cryptonote_connection_context& context, bool check_block_queue) const
{
	// take out blocks we already have
	size_t skip = 0;
	while (skip < context.m_needed_objects.size() && (m_core.have_block(context.m_needed_objects[skip].first) || (check_block_queue && m_block_queue.have(context.m_needed_objects[skip].first))))
	{
		// if we're popping the last hash, record it so we can ask again from that hash,
		// this prevents never being able to progress on peers we get old hash lists from
		if (skip + 1 == context.m_needed_objects.size())
			context.m_last_known_hash = context.m_needed_objects[skip].first;
		++skip;
	}
	if (skip > 0)
	{
		GULPSF_LOG_L1("{} skipping {}/{} blocks", context_str, skip, context.m_needed_objects.size());
		context.m_needed_objects = std::vector<std::pair<crypto::hash, uint64_t>>(context.m_needed_objects.begin() + skip, context.m_needed_objects.end());
	}
	return skip;
}
//------------------------------------------------------------------------------------------------------------------------
template<class t_core>
bool t_cryptonote_protocol_handler<t_core>::request_missing_objects(cryptonote_connection_context& context, bool check_having_blocks, bool force_next_span)
{
// flush stale spans
	std::set<boost::uuids::uuid> live_connections;
	m_p2p->for_each_connection([&](cryptonote_connection_context& context, nodetool::peerid_type peer_id, uint32_t support_flags)->bool{
	live_connections.insert(context.m_connection_id);
	return true;
	});
	m_block_queue.flush_stale_spans(live_connections);

	// if we don't need to get next span, and the block queue is full enough, wait a bit
	bool start_from_current_chain = false;
	if (!force_next_span)
	{
	do
	{
		size_t nspans = m_block_queue.get_num_filled_spans();
		size_t size = m_block_queue.get_data_size();
		const uint64_t bc_height = m_core.get_current_blockchain_height();
		const size_t block_queue_size_threshold = m_block_download_max_size ? m_block_download_max_size : BLOCK_QUEUE_SIZE_THRESHOLD;
		bool queue_proceed = nspans < BLOCK_QUEUE_NSPANS_THRESHOLD || size < block_queue_size_threshold;
		// get rid of blocks we already requested, or already have
		if (skip_unneeded_hashes(context, true) && context.m_needed_objects.empty() && context.m_num_requested == 0)
		{
			if (context.m_remote_blockchain_height > m_block_queue.get_next_needed_height(bc_height))
			{
				GULPS_LOG_ERROR("{} Nothing we can request from this peer, and we did not request anything previously", context_str);
				return false;
			}
			GULPS_LOG_L1(context_str, "Nothing to get from this peer, and it's not ahead of us, all done");
			context.m_state = cryptonote_connection_context::state_normal;
			if (m_core.get_current_blockchain_height() >= m_core.get_target_blockchain_height())
				on_connection_synchronized();
			return true;
		}
		uint64_t next_needed_height = m_block_queue.get_next_needed_height(bc_height);
		uint64_t next_block_height;
		if (context.m_needed_objects.empty())
			next_block_height = next_needed_height;
		else
			next_block_height = context.m_last_response_height - context.m_needed_objects.size() + 1;
		bool proceed = queue_proceed;
		GULPS_LOG_L1("last_response_height=", context.m_last_response_height, ", m_needed_objects size=", context.m_needed_objects.size());

		// if we're waiting for next span, try to get it before unblocking threads below,
		// or a runaway downloading of future spans might happen
		if (should_download_next_span(context, true))
		{
			GULPS_LOG_L1(context_str, "We should try for that next span too, resuming");
			force_next_span = true;
			GULPS_LOG_L1("resuming");
			break;
		}

		if (proceed)
		{
			if (context.m_state != cryptonote_connection_context::state_standby)
			{
				GULPS_LOG_L1(context_str, "Block queue is ", nspans, " and ", size, ", resuming");
				GULPS_LOG_L1("resuming");
			}
			break;
		}

		// this one triggers if all threads are in standby, which should not happen,
		// but happened at least once, so we unblock at least one thread if so
		boost::unique_lock<boost::mutex> sync{m_sync_lock, boost::try_to_lock};
		if (sync.owns_lock())
		{
			bool filled = false;
			boost::posix_time::ptime time;
			boost::uuids::uuid connection_id;
			if (m_block_queue.has_next_span(m_core.get_current_blockchain_height(), filled, time, connection_id) && filled)
			{
				GULPS_LOG_L1(context_str, "No other thread is adding blocks, and next span needed is ready, resuming");
				GULPS_LOG_L1("resuming");
				context.m_state = cryptonote_connection_context::state_standby;
				++context.m_callback_request_count;
				m_p2p->request_callback(context);
				return true;
			}
			else
			{
				sync.unlock();

				// if this has gone on for too long, drop incoming connection to guard against some wedge state
				if (!context.m_is_income)
				{
					const uint64_t now = tools::get_tick_count();
					const uint64_t dt = now - m_last_add_end_time;
					if (m_last_add_end_time && tools::ticks_to_ns(dt) >= DROP_ON_SYNC_WEDGE_THRESHOLD)
					{
						GULPS_LOG_L1(context_str, "ns ", tools::ticks_to_ns(dt), " from ", m_last_add_end_time, " and ", now);
						GULPS_LOG_L1(context_str, "Block addition seems to have wedged, dropping connection");
						return false;
					}
				}
			}
		}

		if (context.m_state != cryptonote_connection_context::state_standby)
		{
			if (!queue_proceed)
				GULPS_LOG_L1(context_str, "Block queue is ", nspans, " and ", size, ", pausing");
			else if (!stripe_proceed_main && !stripe_proceed_secondary)
				GULPS_LOG_L1(context_str, "We do not have the stripe required to download another block, pausing");
			context.m_state = cryptonote_connection_context::state_standby;
			GULPS_LOG_L1("pausing");
		}

		return true;
	} while(0);
	context.m_state = cryptonote_connection_context::state_synchronizing;
	}

   	GULPS_LOG_L1("request_missing_objects: check=", check_having_blocks, ", force_next_span=", force_next_span,
        ", m_needed_objects=", context.m_needed_objects.size(), ", lrh=", context.m_last_response_height,
        ", chain=", m_core.get_current_blockchain_height());

	if(context.m_needed_objects.size() || force_next_span)
	{
		//we know objects that we need, request this objects
		NOTIFY_REQUEST_GET_OBJECTS::request req;
		bool is_next = false;
		size_t count = 0;
		const size_t count_limit = m_core.get_block_sync_size(m_core.get_current_blockchain_height());
		std::pair<uint64_t, uint64_t> span = std::make_pair(0, 0);
		if (force_next_span)
		{
			if (span.second == 0)
			{
				std::vector<crypto::hash> hashes;
				boost::uuids::uuid span_connection_id;
				boost::posix_time::ptime time;
				span = m_block_queue.get_next_span_if_scheduled(hashes, span_connection_id, time);
				if (span.second > 0)
				{
					is_next = true;
					req.blocks.reserve(hashes.size());
					for (const auto &hash: hashes)
					{
						req.blocks.push_back(hash);
						context.m_requested_objects.insert(hash);
					}
					m_block_queue.reset_next_span_time();
				}
			}
		}
		if (span.second == 0)
		{
        	GULPS_LOG_L1(context_str, " span size is 0");
			if (context.m_last_response_height + 1 < context.m_needed_objects.size())
			{
				GULPSF_LOG_L1("{} ERROR: inconsistent context: lrh {}, nos {}", context_str, context.m_last_response_height, context.m_needed_objects.size());
				context.m_needed_objects.clear();
				context.m_last_response_height = 0;
				goto skip;
			}
			if (skip_unneeded_hashes(context, false) && context.m_needed_objects.empty() && context.m_num_requested == 0)
			{
				if (context.m_remote_blockchain_height > m_block_queue.get_next_needed_height(m_core.get_current_blockchain_height()))
				{
					GULPS_LOG_ERROR(context_str, "Nothing we can request from this peer, and we did not request anything previously");
					return false;
				}
				GULPS_LOG_L1(context_str, "Nothing to get from this peer, and it's not ahead of us, all done");
				context.m_state = cryptonote_connection_context::state_normal;
				if (m_core.get_current_blockchain_height() >= m_core.get_target_blockchain_height())
					on_connection_synchronized();
				return true;
			}

			const uint64_t first_block_height = context.m_last_response_height - context.m_needed_objects.size() + 1;
			static const uint64_t bp_fork_height = m_core.get_earliest_ideal_height_for_version(8);
			span = m_block_queue.reserve_span(first_block_height, context.m_last_response_height, count_limit, 
				context.m_connection_id, context.m_remote_address, context.m_remote_blockchain_height, context.m_needed_objects);

			GULPSF_LOG_L1(context_str, " span from {}: {} / {}", first_block_height, span.first, span.second);
		}
		if (span.second == 0 && !force_next_span)
		{
			GULPS_LOG_L1(context_str, " still no span reserved, we may be in the corner case of next span scheduled and everything else scheduled/filled");
			std::vector<crypto::hash> hashes;
			boost::uuids::uuid span_connection_id;
			boost::posix_time::ptime time;
			span = m_block_queue.get_next_span_if_scheduled(hashes, span_connection_id, time);
			if (span.second > 0)
			{
				is_next = true;
				req.blocks.reserve(hashes.size());
				for (const auto &hash: hashes)
				{
					req.blocks.push_back(hash);
					++count;
					context.m_requested_objects.insert(hash);
					// that's atrocious O(n) wise, but this is rare
					auto i = std::find_if(context.m_needed_objects.begin(), context.m_needed_objects.end(),
						[&hash](const std::pair<crypto::hash, uint64_t> &o) { return o.first == hash; });
					if (i != context.m_needed_objects.end())
					context.m_needed_objects.erase(i);
				}
			}
		}
		GULPSF_LOG_L1("{} span: {} / {} ({} - {})", context_str, span.first, span.second,  span.first,  (span.first + span.second - 1));
		if (span.second > 0)
		{
			if (!is_next)
			{
				const uint64_t first_context_block_height = context.m_last_response_height - context.m_needed_objects.size() + 1;
				uint64_t skip = span.first - first_context_block_height;
				if (skip > context.m_needed_objects.size())
				{
					GULPS_LOG_ERROR("ERROR: skip {} , m_needed_objects {}, first_context_block_height {}", skip, context.m_needed_objects.size(), first_context_block_height);
					return false;
				}
				if (skip > 0)
					context.m_needed_objects = std::vector<std::pair<crypto::hash, uint64_t>>(context.m_needed_objects.begin() + skip, context.m_needed_objects.end());
				if (context.m_needed_objects.size() < span.second)
				{
					GULPS_LOG_ERROR("ERROR: span {} / {} , m_needed_objects {}", span.first, span.second, context.m_needed_objects.size());
					return false;
				}

				req.blocks.reserve(req.blocks.size() + span.second);
				for (size_t n = 0; n < span.second; ++n)
				{
					req.blocks.push_back(context.m_needed_objects[n].first);
					++count;
					context.m_requested_objects.insert(context.m_needed_objects[n].first);
				}
				context.m_needed_objects = std::vector<std::pair<crypto::hash, uint64_t>>(context.m_needed_objects.begin() + span.second, context.m_needed_objects.end());
			}

			context.m_last_request_time = boost::posix_time::microsec_clock::universal_time();
			context.m_expect_height = span.first;
			context.m_expect_response = NOTIFY_RESPONSE_GET_OBJECTS::ID;
			GULPS_P2P_MESSAGE("-->>NOTIFY_REQUEST_GET_OBJECTS: blocks.size()={} requested blocks count={} / {} from {} , first hash {}", 
				req.blocks.size(), count, count_limit, span.first,req.blocks.front());
			//epee::net_utils::network_throttle_manager::get_global_throttle_inreq().logger_handle_net("log/dr-monero/net/req-all.data", sec, get_avg_block_size());

			context.m_num_requested += req.blocks.size();
			post_notify<NOTIFY_REQUEST_GET_OBJECTS>(req, context);
			GULPS_LOG_L1("requesting objects");
			return true;
		}

		// we can do nothing, so drop this peer to make room for others unless we think we've downloaded all we need
		const uint64_t blockchain_height = m_core.get_current_blockchain_height();
		if (std::max(blockchain_height, m_block_queue.get_next_needed_height(blockchain_height)) >= m_core.get_target_blockchain_height())
		{
			context.m_state = cryptonote_connection_context::state_normal;
			GULPS_LOG_L1("Nothing to do for now, switching to normal state");
			return true;
		}
		GULPS_LOG_L1("We can download nothing from this peer, dropping");
		return false;
	}

skip:
	context.m_needed_objects.clear();

	// we might have been called from the "received chain entry" handler, and end up
	// here because we can't use any of those blocks (maybe because all of them are
	// actually already requested). In this case, if we can add blocks instead, do so
	if (m_core.get_current_blockchain_height() < m_core.get_target_blockchain_height())
	{
		const boost::unique_lock<boost::mutex> sync{m_sync_lock, boost::try_to_lock};
		if (sync.owns_lock())
		{
			uint64_t start_height;
			std::vector<cryptonote::block_complete_entry> blocks;
			boost::uuids::uuid span_connection_id;
			epee::net_utils::network_address span_origin;
			if (m_block_queue.get_next_span(start_height, blocks, span_connection_id, span_origin, true))
			{
				GULPS_LOG_L1(context_str, "No other thread is adding blocks, resuming");
				GULPS_LOG_L1("will try to add blocks next");
				context.m_state = cryptonote_connection_context::state_standby;
				++context.m_callback_request_count;
				m_p2p->request_callback(context);
				return true;
			}
		}
	}

	if(context.m_last_response_height < context.m_remote_blockchain_height-1)
	{
		//we have to fetch more objects ids, request blockchain entry
		NOTIFY_REQUEST_CHAIN::request r = {};
		context.m_expect_height = m_core.get_current_blockchain_height();
		m_core.get_short_chain_history(r.block_ids);
		GULPS_CHECK_AND_ASSERT_MES(!r.block_ids.empty(), false, "Short chain history is empty");

		if (!start_from_current_chain)
		{
			// we'll want to start off from where we are on that peer, which may not be added yet
			if (context.m_last_known_hash != crypto::null_hash && r.block_ids.front() != context.m_last_known_hash)
			{
			context.m_expect_height = std::numeric_limits<uint64_t>::max();
			r.block_ids.push_front(context.m_last_known_hash);
			}
		}

		handler_request_blocks_history( r.block_ids ); // change the limit(?), sleep(?)

		//std::string blob; // for calculate size of request
		//epee::serialization::store_t_to_binary(r, blob);
		//epee::net_utils::network_throttle_manager::get_global_throttle_inreq().logger_handle_net("log/dr-monero/net/req-all.data", sec, get_avg_block_size());
		//LOG_PRINT_CCONTEXT_L1("r = " << 200);

		context.m_last_request_time = boost::posix_time::microsec_clock::universal_time();
		context.m_expect_response = NOTIFY_RESPONSE_CHAIN_ENTRY::ID;
		GULPS_P2P_MESSAGE("-->>NOTIFY_REQUEST_CHAIN: m_block_ids.size()={}, start_from_current_chain {}", r.block_ids.size(), start_from_current_chain);
		post_notify<NOTIFY_REQUEST_CHAIN>(r, context);
		GULPS_LOG_L1("requesting chain");
	}else
	{
		GULPS_CHECK_AND_ASSERT_MES(
			context.m_last_response_height == context.m_remote_blockchain_height - 1 &&
			context.m_needed_objects.empty() &&
			context.m_requested_objects.empty(),
			false,
			"request_missing_blocks final condition failed!",
			"m_last_response_height=", context.m_last_response_height,
			", m_remote_blockchain_height=", context.m_remote_blockchain_height,
			", m_needed_objects.size()=", context.m_needed_objects.size(),
			", m_requested_objects.size()=", context.m_requested_objects.size(),
			", connection=", epee::net_utils::print_connection_context_short(context)
		);

		context.m_state = cryptonote_connection_context::state_normal;
		if (context.m_remote_blockchain_height >= m_core.get_target_blockchain_height())
		{
			if (m_core.get_current_blockchain_height() >= m_core.get_target_blockchain_height())
				on_connection_synchronized();
		}
		else
		{
			GULPSF_LOG_L1("{} we've reached this peer's blockchain height (theirs {} , our target {})", context_str, 
				context.m_remote_blockchain_height, m_core.get_target_blockchain_height());
		}
	}
	return true;
}
//------------------------------------------------------------------------------------------------------------------------
template <class t_core>
bool t_cryptonote_protocol_handler<t_core>::on_connection_synchronized()
{
	bool val_expected = false;
	if(m_synchronized.compare_exchange_strong(val_expected, true))
	{
		if ((current_blockchain_height > m_sync_start_height))
		{
			uint64_t synced_blocks = current_blockchain_height - m_sync_start_height;
			// Report only after syncing an "interesting" number of blocks:
			if (synced_blocks > 20)
			{
				const boost::posix_time::ptime now = boost::posix_time::microsec_clock::universal_time();
				uint64_t synced_seconds = (now - m_sync_start_time).total_seconds();
				if (synced_seconds == 0)
					synced_seconds = 1;
				float blocks_per_second = (1000 * synced_blocks / synced_seconds) / 1000.0f;
				GULPS_GLOBAL_PRINT_CLR(gulps::COLOR_BOLD_YELLOW, 
					"Synced ", synced_blocks, " blocks in ",
					tools::get_human_readable_timespan(synced_seconds), " (", blocks_per_second, " blocks per second)");
			}
		}

		const uint64_t sync_time = m_sync_timer.value();
		const uint64_t add_time = m_add_timer.value();

		GULPS_GLOBAL_PRINT_CLR(gulps::COLOR_BOLD_YELLOW, "\n**********************************************************************\n",
						   "You are now synchronized with the network. You may now start ryo-wallet-cli.\n\n",
						   "Use the \"help\" command to see the list of available commands.\n",
						   "**********************************************************************\n");
		if (sync_time && add_time)
		{
			GULPS_GLOBAL_PRINT_CLR(gulps::COLOR_BOLD_YELLOW, 
				"sync-info", "Sync time: ", sync_time/1e9/60, " min, idle time ",
				(100.f * (1.0f - add_time / (float)sync_time)), "%", ", ",
				(10 * m_sync_download_objects_size / 1024 / 1024) / 10.f, " + ",
				(10 * m_sync_download_chain_size / 1024 / 1024) / 10.f, " MB downloaded.");
		}
		m_core.on_synchronized();
	}
	m_core.safesyncmode(true);
	return true;
}
//------------------------------------------------------------------------------------------------------------------------
template <class t_core>
size_t t_cryptonote_protocol_handler<t_core>::get_synchronizing_connections_count()
{
	size_t count = 0;
	m_p2p->for_each_connection([&](cryptonote_connection_context &context, nodetool::peerid_type peer_id, uint32_t support_flags) -> bool {
		if(context.m_state == cryptonote_connection_context::state_synchronizing)
			++count;
		return true;
	});
	return count;
}
//------------------------------------------------------------------------------------------------------------------------
template <class t_core>
int t_cryptonote_protocol_handler<t_core>::handle_response_chain_entry(int command, NOTIFY_RESPONSE_CHAIN_ENTRY::request &arg, cryptonote_connection_context &context)
{
	GULPS_P2P_MESSAGE("Received NOTIFY_RESPONSE_CHAIN_ENTRY: m_block_ids.size()={}, m_start_height={}, m_total_height={}", arg.m_block_ids.size() , arg.start_height , arg.total_height);

	if (context.m_expect_response != NOTIFY_RESPONSE_CHAIN_ENTRY::ID)
	{
		GULPS_ERROR("Got NOTIFY_RESPONSE_CHAIN_ENTRY out of the blue, dropping connection");
		drop_connection(context, true, false);
		return 1;
	}

	context.m_expect_response = 0;
	if (arg.start_height + 1 > context.m_expect_height) // we expect an overlapping block
	{
		GULPS_ERROR("Got NOTIFY_RESPONSE_CHAIN_ENTRY past expected height, dropping connection");
		drop_connection(context, true, false);
		return 1;
	}

	context.m_last_request_time = boost::date_time::not_a_date_time;
	m_sync_download_chain_size += arg.m_block_ids.size() * sizeof(crypto::hash);

	if(!arg.m_block_ids.size())
	{
		GULPS_ERROR( context_str, "sent empty m_block_ids, dropping connection");
		drop_connection(context, true, false);
		return 1;
	}

	if(arg.total_height < arg.m_block_ids.size() || arg.start_height > arg.total_height - arg.m_block_ids.size())
	{
		GULPS_ERROR( context_str, " sent invalid start/nblocks/height, dropping connection");
		drop_connection(context, true, false);
		return 1;
	}

	if (arg.total_height < context.m_remote_blockchain_height)
	{
		GULPSF_LOG_L1("{}Claims {}, claimed {} before", arg.total_height, context.m_remote_blockchain_height);
		hit_score(context, 1);
	}

	context.m_remote_blockchain_height = arg.total_height;
	context.m_last_response_height = arg.start_height + arg.m_block_ids.size() - 1;
	if(context.m_last_response_height > context.m_remote_blockchain_height)
	{
		GULPSF_LOG_ERROR("{} sent wrong NOTIFY_RESPONSE_CHAIN_ENTRY, with m_total_height={}, m_start_height={}, m_block_ids.size()={}", context_str
					, arg.total_height
					, arg.start_height
					, arg.m_block_ids.size());
		drop_connection(context, false, false);
		return 1;
	}

	uint64_t n_use_blocks = m_core.prevalidate_block_hashes(arg.start_height, arg.m_block_ids);
	if(n_use_blocks + HASH_OF_HASHES_STEP <= arg.m_block_ids.size())
	{
		GULPS_ERROR( context_str, " Most blocks are invalid, dropping connection");
		drop_connection(context, true, false);
		return 1;
	}

	context.m_needed_objects.clear();
	context.m_needed_objects.reserve(arg.m_block_ids.size());
	uint64_t added = 0;
	std::unordered_set<crypto::hash> blocks_found;
	bool first = true;
	bool expect_unknown = false;
	for (size_t i = 0; i < arg.m_block_ids.size(); ++i)
	{
		if (!blocks_found.insert(arg.m_block_ids[i]).second)
		{
			GULPS_ERROR("Duplicate blocks in chain entry response, dropping connection");
			drop_connection_with_score(context, 5, false);
			return 1;
		}
		int where;
		const bool have_block = m_core.have_block_unlocked(arg.m_block_ids[i], &where);
		if (first)
		{
			if (!have_block && !m_block_queue.requested(arg.m_block_ids[i]) && !m_block_queue.have(arg.m_block_ids[i]))
			{
				GULPS_ERROR("First block hash is unknown, dropping connection");
				drop_connection_with_score(context, 5, false);
				return 1;
			}
			if (!have_block)
				expect_unknown = true;
		}
		if (!first)
		{
			// after the first, blocks may be known or unknown, but if they are known,
			// they should be at the same height if on the main chain
			if (have_block)
			{
				switch (where)
				{
					default:
					case HAVE_BLOCK_INVALID:
						GULPS_ERROR("Block is invalid or known without known type, dropping connection");
						drop_connection(context, true, false);
						return 1;
					case HAVE_BLOCK_MAIN_CHAIN:
						if (expect_unknown)
						{
							GULPS_ERROR("Block is on the main chain, but we did not expect a known block, dropping connection");
							drop_connection_with_score(context, 5, false);
							return 1;
						}
						if (m_core.get_block_id_by_height(arg.start_height + i) != arg.m_block_ids[i])
						{
							GULPS_ERROR("Block is on the main chain, but not at the expected height, dropping connection");
							drop_connection_with_score(context, 5, false);
							return 1;
						}
						break;
					case HAVE_BLOCK_ALT_CHAIN:
						if (expect_unknown)
						{
							GULPS_ERROR("Block is on the main chain, but we did not expect a known block, dropping connection");
							drop_connection_with_score(context, 5, false);
							return 1;
						}
						break;
				}
			}
			else
				expect_unknown = true;
		}
		const uint64_t block_weight = arg.m_block_weights.empty() ? 0 : arg.m_block_weights[i];
		context.m_needed_objects.push_back(std::make_pair(arg.m_block_ids[i], block_weight));
		if (++added == n_use_blocks)
			break;
		first = false;
	}

	context.m_last_response_height -= arg.m_block_ids.size() - n_use_blocks;

	if(!request_missing_objects(context, false))
	{
		GULPS_ERROR( context_str, " Failed to request missing objects, dropping connection");
		drop_connection(context, false, false);
		return 1;
	}

	if(arg.total_height > m_core.get_target_blockchain_height())
		m_core.set_target_blockchain_height(arg.total_height);

	return 1;
}
//------------------------------------------------------------------------------------------------------------------------
template <class t_core>
bool t_cryptonote_protocol_handler<t_core>::relay_block(NOTIFY_NEW_BLOCK::request &arg, cryptonote_connection_context &exclude_context)
{
	NOTIFY_NEW_FLUFFY_BLOCK::request fluffy_arg = AUTO_VAL_INIT(fluffy_arg);
	fluffy_arg.current_blockchain_height = arg.current_blockchain_height;
	std::vector<blobdata> fluffy_txs;
	fluffy_arg.b = arg.b;
	fluffy_arg.b.txs = fluffy_txs;

	// pre-serialize them
	std::string fullBlob, fluffyBlob;
	epee::serialization::store_t_to_binary(arg, fullBlob);
	epee::serialization::store_t_to_binary(fluffy_arg, fluffyBlob);

	// sort peers between fluffy ones and others
	std::list<boost::uuids::uuid> fullConnections, fluffyConnections;
	m_p2p->for_each_connection([this, &exclude_context, &fullConnections, &fluffyConnections](connection_context &context, nodetool::peerid_type peer_id, uint32_t support_flags) {
		if(peer_id && exclude_context.m_connection_id != context.m_connection_id)
		{
			if(m_core.fluffy_blocks_enabled() && (support_flags & P2P_SUPPORT_FLAG_FLUFFY_BLOCKS))
			{
				GULPS_LOG_L1( context_str, " PEER SUPPORTS FLUFFY BLOCKS - RELAYING THIN/COMPACT WHATEVER BLOCK");
				fluffyConnections.push_back(context.m_connection_id);
			}
			else
			{
				GULPS_LOG_L1( context_str, " PEER DOESN'T SUPPORT FLUFFY BLOCKS - RELAYING FULL BLOCK");
				fullConnections.push_back(context.m_connection_id);
			}
		}
		return true;
	});

	// send fluffy ones first, we want to encourage people to run that
	m_p2p->relay_notify_to_list(NOTIFY_NEW_FLUFFY_BLOCK::ID, fluffyBlob, fluffyConnections);
	m_p2p->relay_notify_to_list(NOTIFY_NEW_BLOCK::ID, fullBlob, fullConnections);

	return true;
}
//------------------------------------------------------------------------------------------------------------------------
template <class t_core>
bool t_cryptonote_protocol_handler<t_core>::relay_transactions(NOTIFY_NEW_TRANSACTIONS::request &arg, cryptonote_connection_context &exclude_context)
{
	// no check for success, so tell core they're relayed unconditionally
	for(auto tx_blob_it = arg.txs.begin(); tx_blob_it != arg.txs.end(); ++tx_blob_it)
		m_core.on_transaction_relayed(*tx_blob_it);
	return relay_post_notify<NOTIFY_NEW_TRANSACTIONS>(arg, exclude_context);
}
//------------------------------------------------------------------------------------------------------------------------
template<class t_core>
void t_cryptonote_protocol_handler<t_core>::hit_score(cryptonote_connection_context &context, int32_t score)
{
	if (score <= 0)
	{
		GULPS_ERROR("Negative score hit");
		return;
	}
	context.m_score -= score;
	if (context.m_score <= DROP_PEERS_ON_SCORE)
		drop_connection_with_score(context, 5, false);
}
//------------------------------------------------------------------------------------------------------------------------
template<class t_core>
std::string t_cryptonote_protocol_handler<t_core>::get_peers_overview() const
{
	std::stringstream ss;
	const boost::posix_time::ptime now = boost::posix_time::microsec_clock::universal_time();
	m_p2p->for_each_connection([&](const connection_context &ctx, nodetool::peerid_type peer_id, uint32_t support_flags) {
		const uint32_t stripe = tools::get_pruning_stripe(ctx.m_pruning_seed);
		char state_char = cryptonote::get_protocol_state_char(ctx.m_state);
		ss << stripe + state_char;
		if (ctx.m_last_request_time != boost::date_time::not_a_date_time)
			ss << (((now - ctx.m_last_request_time).total_microseconds() > IDLE_PEER_KICK_TIME) ? "!" : "?");
		ss <<  + " ";
		return true;
	});
	return ss.str();
}
//------------------------------------------------------------------------------------------------------------------------
template<class t_core>
void t_cryptonote_protocol_handler<t_core>::drop_connection_with_score(cryptonote_connection_context &context, unsigned score, bool flush_all_spans)
{
	GULPSF_LOG_L1("{}dropping connection id {} (pruning seed P{}), score {}, flush_all_spans {}",
		context_str, context.m_connection_id, epee::string_tools::to_string_hex(context.m_pruning_seed),
		score, flush_all_spans);

	if (score > 0)
		m_p2p->add_host_fail(context.m_remote_address, score);

	m_block_queue.flush_spans(context.m_connection_id, flush_all_spans);

	m_p2p->drop_connection(context);
}
//------------------------------------------------------------------------------------------------------------------------
template <class t_core>
void t_cryptonote_protocol_handler<t_core>::drop_connection(cryptonote_connection_context &context, bool add_fail, bool flush_all_spans)
{
	return drop_connection_with_score(context, add_fail ? 1 : 0, flush_all_spans);
}
//------------------------------------------------------------------------------------------------------------------------
template <class t_core>
void t_cryptonote_protocol_handler<t_core>::on_connection_close(cryptonote_connection_context &context)
{
	uint64_t target = 0;
	m_p2p->for_each_connection([&](const connection_context &cntxt, nodetool::peerid_type peer_id, uint32_t support_flags) {
		if(cntxt.m_state >= cryptonote_connection_context::state_synchronizing && cntxt.m_connection_id != context.m_connection_id)
			target = std::max(target, cntxt.m_remote_blockchain_height);
		return true;
	});
	const uint64_t previous_target = m_core.get_target_blockchain_height();
	if(target < previous_target)
	{
		GULPSF_INFO("Target height decreasing from {} to {}", previous_target , target);
		m_core.set_target_blockchain_height(target);
	}

	m_block_queue.flush_spans(context.m_connection_id, false);
}

//------------------------------------------------------------------------------------------------------------------------
template <class t_core>
void t_cryptonote_protocol_handler<t_core>::stop()
{
	m_stopping = true;
	m_core.stop();
}
} // namespace
