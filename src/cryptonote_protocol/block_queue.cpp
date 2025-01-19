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

#include "block_queue.h"
#include "cryptonote_protocol_defs.h"
#include "string_tools.h"
#include <boost/uuid/nil_generator.hpp>
#include <unordered_map>
#include <vector>

#include "common/gulps.hpp"

GULPS_CAT_MAJOR("blk_queue");

namespace cryptonote
{

void block_queue::add_blocks(uint64_t height, std::vector<cryptonote::block_complete_entry> bcel, const boost::uuids::uuid &connection_id, const epee::net_utils::network_address &addr, float rate, size_t size)
{
	boost::unique_lock<boost::recursive_mutex> lock(mutex);
	std::vector<crypto::hash> hashes;
	bool has_hashes = remove_span(height, &hashes);
	blocks.insert(span(height, std::move(bcel), connection_id, addr, rate, size));
	if (has_hashes)
	{
		for (const crypto::hash &h: hashes)
		{
			requested_hashes.insert(h);
			have_blocks.insert(h);
		}
		set_span_hashes(height, connection_id, hashes);
	}
}

void block_queue::add_blocks(uint64_t height, uint64_t nblocks, const boost::uuids::uuid &connection_id, const epee::net_utils::network_address &addr, boost::posix_time::ptime time)
{
	GULPS_CHECK_AND_ASSERT_THROW_MES(nblocks > 0, "Empty span");
	boost::unique_lock<boost::recursive_mutex> lock(mutex);
	blocks.insert(span(height, nblocks, connection_id, addr, time));
}

void block_queue::flush_spans(const boost::uuids::uuid &connection_id, bool all)
{
	boost::unique_lock<boost::recursive_mutex> lock(mutex);
	block_map::iterator i = blocks.begin();
	while(i != blocks.end())
	{
		block_map::iterator j = i++;
		if (j->connection_id == connection_id && (all || j->blocks.size() == 0))
		{
			erase_block(j);
		}
	}
}

void block_queue::erase_block(block_map::iterator j)
{
	GULPS_CHECK_AND_ASSERT_THROW_MES(j != blocks.end(), "Invalid iterator");
	for (const crypto::hash &h: j->hashes)
	{
		requested_hashes.erase(h);
		have_blocks.erase(h);
	}
	blocks.erase(j);
}

void block_queue::flush_stale_spans(const std::set<boost::uuids::uuid> &live_connections)
{
	boost::unique_lock<boost::recursive_mutex> lock(mutex);
	block_map::iterator i = blocks.begin();
	while(i != blocks.end())
	{
		block_map::iterator j = i++;
		if(j->blocks.empty() && live_connections.find(j->connection_id) == live_connections.end())
		{
			erase_block(j);
		}
	}
}

bool block_queue::remove_span(uint64_t start_block_height, std::vector<crypto::hash> *hashes)
{
	boost::unique_lock<boost::recursive_mutex> lock(mutex);
	for(block_map::iterator i = blocks.begin(); i != blocks.end(); ++i)
	{
		if(i->start_block_height == start_block_height)
		{
			if(hashes)
				*hashes = std::move(i->hashes);
			erase_block(i);
			return true;
		}
	}
	return false;
}

void block_queue::remove_spans(const boost::uuids::uuid &connection_id, uint64_t start_block_height)
{
	boost::unique_lock<boost::recursive_mutex> lock(mutex);
	for(block_map::iterator i = blocks.begin(); i != blocks.end(); )
	{
		block_map::iterator j = i++;
		if(j->connection_id == connection_id && j->start_block_height <= start_block_height)
		{
			erase_block(j);
		}
	}
}

uint64_t block_queue::get_max_block_height() const
{
	boost::unique_lock<boost::recursive_mutex> lock(mutex);
	uint64_t height = 0;
	for(const auto &span : blocks)
	{
		const uint64_t h = span.start_block_height + span.nblocks - 1;
		if(h > height)
			height = h;
	}
	return height;
}

uint64_t block_queue::get_next_needed_height(uint64_t blockchain_height) const
{
	boost::unique_lock<boost::recursive_mutex> lock(mutex);
	if (blocks.empty())
		return blockchain_height;
	uint64_t last_needed_height = blockchain_height;
	bool first = true;
	for (const auto &span: blocks)
	{
		if (span.start_block_height + span.nblocks - 1 < blockchain_height)
			continue;
		if (span.start_block_height != last_needed_height || (first && span.blocks.empty()))
			return last_needed_height;
		last_needed_height = span.start_block_height + span.nblocks;
		first = false;
	}
	return last_needed_height;
}

void block_queue::print() const
{
	boost::unique_lock<boost::recursive_mutex> lock(mutex);
	GULPSF_LOG_L1("Block queue has {} spans", blocks.size() );
	for(const auto &span : blocks)
		GULPSF_LOG_L1("  {} - {} ({}) - {} {} ({} kB/s)", span.start_block_height, (span.start_block_height + span.nblocks - 1), span.nblocks, (span.blocks.empty() ? "scheduled" : "filled    "), boost::uuids::to_string(span.connection_id), ((unsigned)(span.rate * 10 / 1024.f)) / 10.f);
}

std::string block_queue::get_overview() const
{
	boost::unique_lock<boost::recursive_mutex> lock(mutex);
	if(blocks.empty())
		return "[]";
	block_map::const_iterator i = blocks.begin();
	std::string s = std::string("[") + std::to_string(i->start_block_height + i->nblocks - 1) + ":";
	while(++i != blocks.end())
		s += i->blocks.empty() ? "." : "o";
	s += "]";
	return s;
}

inline bool block_queue::requested_internal(const crypto::hash &hash) const
{
	return requested_hashes.find(hash) != requested_hashes.end();
}

bool block_queue::requested(const crypto::hash &hash) const
{
	boost::unique_lock<boost::recursive_mutex> lock(mutex);
	return requested_internal(hash);
}

bool block_queue::have(const crypto::hash &hash) const
{
	boost::unique_lock<boost::recursive_mutex> lock(mutex);
	return have_blocks.find(hash) != have_blocks.end();
}

std::pair<uint64_t, uint64_t> block_queue::reserve_span(uint64_t first_block_height, uint64_t last_block_height, uint64_t max_blocks, const boost::uuids::uuid &connection_id, const epee::net_utils::network_address &addr, uint64_t blockchain_height, const std::vector<crypto::hash> &block_hashes, boost::posix_time::ptime time)
{
	boost::unique_lock<boost::recursive_mutex> lock(mutex);

	GULPSF_LOG_L1("reserve_span: first_block_height {}, last_block_height {}, max {}, blockchain_height {}, block hashes size {}", 
					first_block_height, last_block_height, max_blocks, blockchain_height, block_hashes.size());

	if (last_block_height < first_block_height || max_blocks == 0)
	{
		GULPSF_LOG_L1("reserve_span: early out: first_block_height {}, last_block_height {}, max_blocks {}", first_block_height, last_block_height, max_blocks);
		return std::make_pair(0, 0);
	}

	if (block_hashes.size() > last_block_height)
	{
		GULPSF_LOG_L1("reserve_span: more block hashes than fit within last_block_height: {} and {}", block_hashes.size(), last_block_height);
		return std::make_pair(0, 0);
	}

	// skip everything we've already requested
	uint64_t span_start_height = last_block_height - block_hashes.size() + 1;
	auto i = block_hashes.begin();
	while (i != block_hashes.end() && requested_internal((*i)))
	{
		++i;
		++span_start_height;
	}

	const uint64_t block_hashes_start_height = last_block_height - block_hashes.size() + 1;
	if (span_start_height >= block_hashes.size() + block_hashes_start_height)
	{
		GULPSF_LOG_L1("Out of hashes, cannot reserve");
		return std::make_pair(0, 0);
	}

	i = block_hashes.begin() + span_start_height - block_hashes_start_height;
	while (i != block_hashes.end() && requested_internal((*i)))
	{
		++i;
		++span_start_height;
	}

	uint64_t span_length = 0;
	std::vector<crypto::hash> hashes;

	while (i != block_hashes.end() && span_length < max_blocks)
	{
		hashes.push_back((*i));
		++i;
		++span_length;
	}

	if (span_length == 0)
	{
		GULPSF_LOG_L1("span_length 0, cannot reserve");
		return std::make_pair(0, 0);
	}

	GULPSF_LOG_L1("Reserving span {} - {} for {}", span_start_height, (span_start_height + span_length - 1), boost::uuids::to_string(connection_id));
	add_blocks(span_start_height, span_length, connection_id, addr, time);
	set_span_hashes(span_start_height, connection_id, hashes);
	
	return std::make_pair(span_start_height, span_length);
}

std::pair<uint64_t, uint64_t> block_queue::get_next_span_if_scheduled(std::vector<crypto::hash> &hashes, boost::uuids::uuid &connection_id, boost::posix_time::ptime &time) const
{
	boost::unique_lock<boost::recursive_mutex> lock(mutex);
	if (blocks.empty())
		return std::make_pair(0, 0);
	block_map::const_iterator i = blocks.begin();
	if (i == blocks.end())
		return std::make_pair(0, 0);
	if (!i->blocks.empty())
		return std::make_pair(0, 0);
	hashes = i->hashes;
	connection_id = i->connection_id;
	time = i->time;
	return std::make_pair(i->start_block_height, i->nblocks);
}

void block_queue::reset_next_span_time(boost::posix_time::ptime t)
{
	boost::unique_lock<boost::recursive_mutex> lock(mutex);
	GULPS_CHECK_AND_ASSERT_THROW_MES(!blocks.empty(), "No next span to reset time");
	block_map::iterator i = blocks.begin();
	GULPS_CHECK_AND_ASSERT_THROW_MES(i != blocks.end(), "No next span to reset time");
	GULPS_CHECK_AND_ASSERT_THROW_MES(i->blocks.empty(), "Next span is not empty");
	(boost::posix_time::ptime&)i->time = t; // sod off, time doesn't influence sorting
}

void block_queue::set_span_hashes(uint64_t start_height, const boost::uuids::uuid &connection_id, std::vector<crypto::hash> hashes)
{
	boost::unique_lock<boost::recursive_mutex> lock(mutex);
	for (block_map::iterator i = blocks.begin(); i != blocks.end(); ++i)
	{
		if (i->start_block_height == start_height && i->connection_id == connection_id)
		{
			span s = *i;
			erase_block(i);
			s.hashes = std::move(hashes);
			for (const crypto::hash &h: s.hashes)
				requested_hashes.insert(h);
			blocks.insert(s);
			return;
		}
	}
}

bool block_queue::get_next_span(uint64_t &height, std::vector<cryptonote::block_complete_entry> &bcel, boost::uuids::uuid &connection_id, epee::net_utils::network_address &addr, bool filled) const
{
	boost::unique_lock<boost::recursive_mutex> lock(mutex);
	if (blocks.empty())
		return false;
	block_map::const_iterator i = blocks.begin();
	for (; i != blocks.end(); ++i)
	{
		if (!filled || !i->blocks.empty())
		{
			height = i->start_block_height;
			bcel = i->blocks;
			connection_id = i->connection_id;
			addr = i->origin;
			return true;
		}
	}
	return false;
}

bool block_queue::has_next_span(const boost::uuids::uuid &connection_id, bool &filled, boost::posix_time::ptime &time) const
{
  boost::unique_lock<boost::recursive_mutex> lock(mutex);
	if (blocks.empty())
		return false;
	block_map::const_iterator i = blocks.begin();
	if (i == blocks.end())
		return false;
	if (i->connection_id != connection_id)
		return false;
	filled = !i->blocks.empty();
	time = i->time;
	return true;
}

bool block_queue::has_next_span(uint64_t height, bool &filled, boost::posix_time::ptime &time, boost::uuids::uuid &connection_id) const
{
	boost::unique_lock<boost::recursive_mutex> lock(mutex);
	if(blocks.empty())
		return false;
	block_map::const_iterator i = blocks.begin();
	if(i == blocks.end())
		return false;
	if(i->start_block_height > height)
		return false;
	filled = !i->blocks.empty();
	time = i->time;
	connection_id = i->connection_id;
	return true;
}

size_t block_queue::get_data_size() const
{
	boost::unique_lock<boost::recursive_mutex> lock(mutex);
	size_t size = 0;
	for(const auto &span : blocks)
		size += span.size;
	return size;
}

size_t block_queue::get_num_filled_spans_prefix() const
{
	boost::unique_lock<boost::recursive_mutex> lock(mutex);

	if (blocks.empty())
		return 0;
	block_map::const_iterator i = blocks.begin();
	size_t size = 0;
	while (i != blocks.end() && !i->blocks.empty())
	{
		++i;
		++size;
	}
	return size;
}

size_t block_queue::get_num_filled_spans() const
{
	boost::unique_lock<boost::recursive_mutex> lock(mutex);
	size_t size = 0;
	for(const auto &span : blocks)
		if(!span.blocks.empty())
			++size;
	return size;
}

crypto::hash block_queue::get_last_known_hash(const boost::uuids::uuid &connection_id) const
{
	boost::unique_lock<boost::recursive_mutex> lock(mutex);
	crypto::hash hash = crypto::null_hash;
	uint64_t highest_height = 0;
	for(const auto &span : blocks)
	{
		if(span.connection_id != connection_id)
			continue;
		uint64_t h = span.start_block_height + span.nblocks - 1;
		if(h > highest_height && span.hashes.size() == span.nblocks)
		{
			hash = span.hashes.back();
			highest_height = h;
		}
	}
	return hash;
}

bool block_queue::has_spans(const boost::uuids::uuid &connection_id) const
{
	for(const auto &span : blocks)
	{
		if(span.connection_id == connection_id)
			return true;
	}
	return false;
}

float block_queue::get_speed(const boost::uuids::uuid &connection_id) const
{
	boost::unique_lock<boost::recursive_mutex> lock(mutex);
	std::unordered_map<boost::uuids::uuid, float> speeds;
	for(const auto &span : blocks)
	{
		if(span.blocks.empty())
			continue;
		// note that the average below does not average over the whole set, but over the
		// previous pseudo average and the latest rate: this gives much more importance
		// to the latest measurements, which is fine here
		std::unordered_map<boost::uuids::uuid, float>::iterator i = speeds.find(span.connection_id);
		if(i == speeds.end())
			speeds.insert(std::make_pair(span.connection_id, span.rate));
		else
			i->second = (i->second + span.rate) / 2;
	}
	float conn_rate = -1, best_rate = 0;
	for(const auto &i : speeds)
	{
		if(i.first == connection_id)
			conn_rate = i.second;
		if(i.second > best_rate)
			best_rate = i.second;
	}

	if(conn_rate <= 0)
		return 1.0f; // not found, assume good speed
	if(best_rate == 0)
		return 1.0f; // everything dead ? Can't happen, but let's trap anyway

	const float speed = conn_rate / best_rate;
	GULPSF_LOG_L2(" Relative speed for {}: {} ({}/{})", boost::uuids::to_string(connection_id) , speed , conn_rate , best_rate);
	return speed;
}

bool block_queue::foreach(std::function<bool(const span&)> f) const
{
	boost::unique_lock<boost::recursive_mutex> lock(mutex);
	block_map::const_iterator i = blocks.begin();
	while(i != blocks.end())
		if (!f(*i++))
			return false;
	return true;
}

}
